#![cfg_attr(not(test), no_std)]

extern crate alloc;

// TODO:
// - add type checks
// - add malleability checks
// - add stack limits and other safety checks

mod cleartext;
mod time;

pub use cleartext::*;

use alloc::{boxed::Box, string::String, vec, vec::Vec};

#[cfg(test)]
use alloc::{format, string::ToString};

use core::str::FromStr;

use hex::{self, FromHex};

use bitcoin::{
    bip32::{ChildNumber, Xpub},
    consensus::{encode, Decodable, Encodable},
    io::Read,
    VarInt,
};

const HARDENED_INDEX: u32 = 0x80000000u32;
const MAX_OLDER_AFTER: u32 = 2147483647; // maximum allowed in older/after

// Maximum key count for `multi`/`sortedmulti` (OP_CHECKMULTISIG consensus limit).
const MAX_KEYS_MULTI: usize = 20;
// Maximum key count for the Taproot `multi_a`/`sortedmulti_a` variants.
const MAX_KEYS_MULTI_A: usize = 999;
// Maximum recursion depth for descriptor parsing. Bounds host-provided nesting
// (e.g. `andor(...andor(...))` or `{{{...}}}`) to keep stack usage finite on
// the constrained VM. Well above any realistic policy depth.
const MAX_PARSE_DEPTH: usize = 64;
// Maximum byte length of a serialized descriptor template accepted by
// `WalletPolicy::deserialize`. Practical policies are far below this.
const MAX_SERIALIZED_DESCRIPTORTEMPLATE_LEN: usize = 4096;
// Maximum number of key information entries accepted by `WalletPolicy::deserialize`.
// Matches the largest multi-key fragment we can produce (`multi_a`/`sortedmulti_a`).
const MAX_SERIALIZED_KEY_COUNT: usize = MAX_KEYS_MULTI_A;
// Maximum length of a serialized BIP-32 derivation path.
const MAX_BIP32_DERIVATION_PATH_LEN: usize = 32;

/// Error type for descriptor template / wallet policy parsing and serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Input string was empty when content was expected.
    EmptyInput,
    /// Parsing succeeded but left unconsumed input.
    TrailingInput,
    /// A required syntactic token was missing or unexpected.
    InvalidSyntax,
    /// Hex-encoded data was not valid hex.
    InvalidHex,
    /// A key, xpub, fingerprint, hash, or compressed-key byte was invalid.
    InvalidKey,
    /// A numeric literal was out of range or had illegal leading zeros.
    NumberOutOfRange,
    /// A data field was the wrong length.
    InvalidLength,
    /// An unrecognized descriptor fragment keyword was encountered.
    UnrecognizedFragment,
    /// A multisig/sortedmulti fragment had fewer than 2 key placeholders.
    TooFewKeyExpressions,
    /// The threshold `k` in `thresh(k, ...)` exceeds the number of sub-scripts.
    ThreshExceedsScripts,
    /// A key placeholder index was out of range for the key-information list.
    InvalidKeyIndex,
    /// The top-level descriptor type is not supported.
    InvalidTopLevelPolicy,
    /// Writing a descriptor to a `String` buffer failed.
    FormatError,
    /// `sh`/`wsh`/`wpkh`/`musig` used in a position that is not allowed by the spec.
    InvalidScriptContext,
    /// Too many keys for a multisig fragment.
    TooManyKeys,
    /// Invalid multisig quorum (threshold).
    InvalidMultisigQuorum,
    /// Descriptor template nesting exceeds [`MAX_PARSE_DEPTH`].
    NestingTooDeep,
    /// The two multipath indices in `/<M;N>/*` are equal (they must be distinct).
    NonDistinctMultipath,
    /// A wallet policy has no key placeholders (at least one is required).
    NoKeyPlaceholders,
    /// The referenced key placeholders do not match the key information vector:
    /// some index is unused, or the counts differ.
    KeyIndexCountMismatch,
    /// The key information vector contains duplicate public keys (they must be
    /// pairwise distinct).
    DuplicateKey,
    /// The same key placeholder is used with overlapping multipath index sets
    /// (`{M,N}` and `{P,Q}` must be disjoint).
    OverlappingMultipath,
}

/// The parsing context, tracking which top-level descriptor we are inside.
/// This determines which fragments and key expression forms are valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseContext {
    /// Top-level: no enclosing descriptor yet.
    TopLevel,
    /// Inside a `sh()` descriptor (legacy P2SH).
    Legacy,
    /// Inside a top-level `wsh()` descriptor (native segwit).
    Segwit,
    /// Inside `sh(wsh())` (wrapped segwit).
    WrappedSegwit,
    /// Inside a `tr()` descriptor (BIP-390: musig allowed).
    Taproot,
}

impl ParseContext {
    fn musig_allowed(self) -> bool {
        matches!(self, ParseContext::Taproot)
    }

    /// `sh()` is only allowed at the top level.
    fn sh_allowed(self) -> bool {
        matches!(self, ParseContext::TopLevel)
    }

    /// `wpkh()` is only allowed at the top level or inside `sh()`.
    fn wpkh_allowed(self) -> bool {
        matches!(self, ParseContext::TopLevel | ParseContext::Legacy)
    }

    /// `wsh()` is only allowed at the top level or inside `sh()`.
    fn wsh_allowed(self) -> bool {
        matches!(self, ParseContext::TopLevel | ParseContext::Legacy)
    }

    /// `tr()` is only allowed at the top level.
    fn tr_allowed(self) -> bool {
        matches!(self, ParseContext::TopLevel)
    }

    /// `multi()`/`sortedmulti()` are only allowed inside `sh()` or `wsh()`.
    fn multi_allowed(self) -> bool {
        matches!(
            self,
            ParseContext::Legacy | ParseContext::Segwit | ParseContext::WrappedSegwit
        )
    }

    /// `multi_a()`/`sortedmulti_a()` are tapscript-only, so allowed only inside `tr()`.
    fn multi_a_allowed(self) -> bool {
        matches!(self, ParseContext::Taproot)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeyOrigin {
    pub fingerprint: u32,
    pub derivation_path: Vec<ChildNumber>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeyInformation {
    pub pubkey: Xpub,
    pub origin_info: Option<KeyOrigin>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum KeyExpressionType {
    PlainKey(u32),
    Musig(Vec<u32>),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeyExpression {
    pub key_type: KeyExpressionType,
    pub num1: u32,
    pub num2: u32,
}

impl KeyExpression {
    pub fn plain(key_index: u32, num1: u32, num2: u32) -> Self {
        KeyExpression {
            key_type: KeyExpressionType::PlainKey(key_index),
            num1,
            num2,
        }
    }

    pub fn is_plain(&self) -> bool {
        matches!(self.key_type, KeyExpressionType::PlainKey(_))
    }

    pub fn musig(key_indices: Vec<u32>, num1: u32, num2: u32) -> Self {
        KeyExpression {
            key_type: KeyExpressionType::Musig(key_indices),
            num1,
            num2,
        }
    }

    pub fn is_musig(&self) -> bool {
        matches!(self.key_type, KeyExpressionType::Musig(_))
    }

    /// Returns the key index for a plain key expression.
    /// Returns `None` for musig key expressions.
    pub fn plain_key_index(&self) -> Option<u32> {
        match &self.key_type {
            KeyExpressionType::PlainKey(idx) => Some(*idx),
            KeyExpressionType::Musig(_) => None,
        }
    }

    /// Returns the key indices for a musig key expression.
    /// Returns `None` for plain key expressions.
    pub fn musig_key_indices(&self) -> Option<&Vec<u32>> {
        match &self.key_type {
            KeyExpressionType::Musig(indices) => Some(indices),
            KeyExpressionType::PlainKey(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum DescriptorTemplate {
    Sh(Box<DescriptorTemplate>),
    Wsh(Box<DescriptorTemplate>),
    Pkh(KeyExpression),
    Wpkh(KeyExpression),
    Sortedmulti(u32, Vec<KeyExpression>),
    Sortedmulti_a(u32, Vec<KeyExpression>),
    Tr(KeyExpression, Option<TapTree>),

    Zero,
    One,
    Pk(KeyExpression),
    Pk_k(KeyExpression),
    Pk_h(KeyExpression),
    Older(u32),
    After(u32),
    Sha256([u8; 32]),
    Ripemd160([u8; 20]),
    Hash256([u8; 32]),
    Hash160([u8; 20]),
    Andor(
        Box<DescriptorTemplate>,
        Box<DescriptorTemplate>,
        Box<DescriptorTemplate>,
    ),
    And_v(Box<DescriptorTemplate>, Box<DescriptorTemplate>),
    And_b(Box<DescriptorTemplate>, Box<DescriptorTemplate>),
    And_n(Box<DescriptorTemplate>, Box<DescriptorTemplate>),
    Or_b(Box<DescriptorTemplate>, Box<DescriptorTemplate>),
    Or_c(Box<DescriptorTemplate>, Box<DescriptorTemplate>),
    Or_d(Box<DescriptorTemplate>, Box<DescriptorTemplate>),
    Or_i(Box<DescriptorTemplate>, Box<DescriptorTemplate>),
    Thresh(u32, Vec<DescriptorTemplate>),
    Multi(u32, Vec<KeyExpression>),
    Multi_a(u32, Vec<KeyExpression>),

    // wrappers
    A(Box<DescriptorTemplate>),
    S(Box<DescriptorTemplate>),
    C(Box<DescriptorTemplate>),
    T(Box<DescriptorTemplate>),
    D(Box<DescriptorTemplate>),
    V(Box<DescriptorTemplate>),
    J(Box<DescriptorTemplate>),
    N(Box<DescriptorTemplate>),
    L(Box<DescriptorTemplate>),
    U(Box<DescriptorTemplate>),
}

pub struct DescriptorTemplateIter<'a> {
    placeholders: alloc::vec::IntoIter<(&'a KeyExpression, Option<&'a DescriptorTemplate>)>,
}

impl<'a> From<&'a DescriptorTemplate> for DescriptorTemplateIter<'a> {
    fn from(desc: &'a DescriptorTemplate) -> Self {
        let mut placeholders = Vec::new();
        desc.collect_placeholders(None, &mut placeholders);
        DescriptorTemplateIter {
            placeholders: placeholders.into_iter(),
        }
    }
}

impl<'a> Iterator for DescriptorTemplateIter<'a> {
    type Item = (&'a KeyExpression, Option<&'a DescriptorTemplate>);

    fn next(&mut self) -> Option<Self::Item> {
        self.placeholders.next()
    }
}

/// Mutable iterator over the key placeholders of a [`DescriptorTemplate`].
///
/// Yields `&mut KeyExpression` in the same traversal order as
/// [`DescriptorTemplateIter`] (the immutable counterpart), so that in-place
/// mutations preserve the canonical ordering expected by
/// `are_key_derivations_canonical`.
pub struct DescriptorTemplateIterMut<'a> {
    placeholders: alloc::vec::IntoIter<&'a mut KeyExpression>,
}

impl<'a> Iterator for DescriptorTemplateIterMut<'a> {
    type Item = &'a mut KeyExpression;

    fn next(&mut self) -> Option<Self::Item> {
        self.placeholders.next()
    }
}

impl DescriptorTemplate {
    /// Determines if root fragment is a wrapper.
    fn is_wrapper(&self) -> bool {
        matches!(
            self,
            DescriptorTemplate::A(_)
                | DescriptorTemplate::S(_)
                | DescriptorTemplate::C(_)
                | DescriptorTemplate::T(_)
                | DescriptorTemplate::D(_)
                | DescriptorTemplate::V(_)
                | DescriptorTemplate::J(_)
                | DescriptorTemplate::N(_)
                | DescriptorTemplate::L(_)
                | DescriptorTemplate::U(_)
        )
    }
    pub fn placeholders(&self) -> DescriptorTemplateIter<'_> {
        DescriptorTemplateIter::from(self)
    }

    pub fn placeholders_mut(&mut self) -> DescriptorTemplateIterMut<'_> {
        let mut placeholders = Vec::new();
        self.collect_placeholders_mut(&mut placeholders);
        DescriptorTemplateIterMut {
            placeholders: placeholders.into_iter(),
        }
    }

    /// Appends every key placeholder to `out` in left-to-right pre-order,
    /// tagging each with the `tr(...)` tap-leaf it belongs to (`None` for the
    /// taproot internal key and for keys outside any tap-tree). This single
    /// recursive traversal backs [`DescriptorTemplateIter`];
    /// [`Self::collect_placeholders_mut`] is its `&mut` twin and visits
    /// fragments in the identical order.
    fn collect_placeholders<'a>(
        &'a self,
        leaf_ctx: Option<&'a DescriptorTemplate>,
        out: &mut Vec<(&'a KeyExpression, Option<&'a DescriptorTemplate>)>,
    ) {
        match self {
            DescriptorTemplate::Sh(sub)
            | DescriptorTemplate::Wsh(sub)
            | DescriptorTemplate::A(sub)
            | DescriptorTemplate::S(sub)
            | DescriptorTemplate::C(sub)
            | DescriptorTemplate::T(sub)
            | DescriptorTemplate::D(sub)
            | DescriptorTemplate::V(sub)
            | DescriptorTemplate::J(sub)
            | DescriptorTemplate::N(sub)
            | DescriptorTemplate::L(sub)
            | DescriptorTemplate::U(sub) => sub.collect_placeholders(leaf_ctx, out),

            DescriptorTemplate::Andor(a, b, c) => {
                a.collect_placeholders(leaf_ctx, out);
                b.collect_placeholders(leaf_ctx, out);
                c.collect_placeholders(leaf_ctx, out);
            }

            DescriptorTemplate::Or_b(a, b)
            | DescriptorTemplate::Or_c(a, b)
            | DescriptorTemplate::Or_d(a, b)
            | DescriptorTemplate::Or_i(a, b)
            | DescriptorTemplate::And_v(a, b)
            | DescriptorTemplate::And_b(a, b)
            | DescriptorTemplate::And_n(a, b) => {
                a.collect_placeholders(leaf_ctx, out);
                b.collect_placeholders(leaf_ctx, out);
            }

            DescriptorTemplate::Tr(key, tree) => {
                out.push((key, None));
                if let Some(tree) = tree {
                    for leaf in tree.tapleaves() {
                        leaf.collect_placeholders(Some(leaf), out);
                    }
                }
            }

            DescriptorTemplate::Pkh(key)
            | DescriptorTemplate::Wpkh(key)
            | DescriptorTemplate::Pk(key)
            | DescriptorTemplate::Pk_k(key)
            | DescriptorTemplate::Pk_h(key) => out.push((key, leaf_ctx)),

            DescriptorTemplate::Sortedmulti(_, keys)
            | DescriptorTemplate::Sortedmulti_a(_, keys)
            | DescriptorTemplate::Multi(_, keys)
            | DescriptorTemplate::Multi_a(_, keys) => {
                for key in keys {
                    out.push((key, leaf_ctx));
                }
            }

            DescriptorTemplate::Thresh(_, subs) => {
                for sub in subs {
                    sub.collect_placeholders(leaf_ctx, out);
                }
            }

            DescriptorTemplate::Zero
            | DescriptorTemplate::One
            | DescriptorTemplate::Older(_)
            | DescriptorTemplate::After(_)
            | DescriptorTemplate::Sha256(_)
            | DescriptorTemplate::Ripemd160(_)
            | DescriptorTemplate::Hash256(_)
            | DescriptorTemplate::Hash160(_) => {}
        }
    }

    /// `&mut` twin of [`Self::collect_placeholders`]: appends every placeholder
    /// in the identical order (no leaf context is tracked). Kept safe by
    /// descending through disjoint `&mut` sub-borrows rather than raw pointers.
    fn collect_placeholders_mut<'a>(&'a mut self, out: &mut Vec<&'a mut KeyExpression>) {
        match self {
            DescriptorTemplate::Sh(sub)
            | DescriptorTemplate::Wsh(sub)
            | DescriptorTemplate::A(sub)
            | DescriptorTemplate::S(sub)
            | DescriptorTemplate::C(sub)
            | DescriptorTemplate::T(sub)
            | DescriptorTemplate::D(sub)
            | DescriptorTemplate::V(sub)
            | DescriptorTemplate::J(sub)
            | DescriptorTemplate::N(sub)
            | DescriptorTemplate::L(sub)
            | DescriptorTemplate::U(sub) => sub.collect_placeholders_mut(out),

            DescriptorTemplate::Andor(a, b, c) => {
                a.collect_placeholders_mut(out);
                b.collect_placeholders_mut(out);
                c.collect_placeholders_mut(out);
            }

            DescriptorTemplate::Or_b(a, b)
            | DescriptorTemplate::Or_c(a, b)
            | DescriptorTemplate::Or_d(a, b)
            | DescriptorTemplate::Or_i(a, b)
            | DescriptorTemplate::And_v(a, b)
            | DescriptorTemplate::And_b(a, b)
            | DescriptorTemplate::And_n(a, b) => {
                a.collect_placeholders_mut(out);
                b.collect_placeholders_mut(out);
            }

            DescriptorTemplate::Tr(key, tree) => {
                out.push(key);
                if let Some(tree) = tree {
                    tree.collect_leaf_placeholders_mut(out);
                }
            }

            DescriptorTemplate::Pkh(key)
            | DescriptorTemplate::Wpkh(key)
            | DescriptorTemplate::Pk(key)
            | DescriptorTemplate::Pk_k(key)
            | DescriptorTemplate::Pk_h(key) => out.push(key),

            DescriptorTemplate::Sortedmulti(_, keys)
            | DescriptorTemplate::Sortedmulti_a(_, keys)
            | DescriptorTemplate::Multi(_, keys)
            | DescriptorTemplate::Multi_a(_, keys) => {
                for key in keys.iter_mut() {
                    out.push(key);
                }
            }

            DescriptorTemplate::Thresh(_, subs) => {
                for sub in subs.iter_mut() {
                    sub.collect_placeholders_mut(out);
                }
            }

            DescriptorTemplate::Zero
            | DescriptorTemplate::One
            | DescriptorTemplate::Older(_)
            | DescriptorTemplate::After(_)
            | DescriptorTemplate::Sha256(_)
            | DescriptorTemplate::Ripemd160(_)
            | DescriptorTemplate::Hash256(_)
            | DescriptorTemplate::Hash160(_) => {}
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TapTree {
    Script(Box<DescriptorTemplate>),
    Branch(Box<TapTree>, Box<TapTree>),
}

impl TapTree {
    pub fn tapleaves(&self) -> TapleavesIter<'_> {
        TapleavesIter::new(self)
    }

    /// Appends the placeholders of every tap-leaf to `out`, mutably, in the
    /// same left-to-right leaf order as [`TapleavesIter`]. Stays safe by
    /// recursing through the tree's disjoint `&mut` sub-borrows.
    fn collect_leaf_placeholders_mut<'a>(&'a mut self, out: &mut Vec<&'a mut KeyExpression>) {
        match self {
            TapTree::Script(desc) => desc.collect_placeholders_mut(out),
            TapTree::Branch(left, right) => {
                left.collect_leaf_placeholders_mut(out);
                right.collect_leaf_placeholders_mut(out);
            }
        }
    }
}

pub struct TapleavesIter<'a> {
    stack: Vec<&'a TapTree>,
}

impl<'a> TapleavesIter<'a> {
    fn new(root: &'a TapTree) -> Self {
        TapleavesIter { stack: vec![root] }
    }
}

impl<'a> Iterator for TapleavesIter<'a> {
    type Item = &'a DescriptorTemplate;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(node) = self.stack.pop() {
            match node {
                TapTree::Script(descriptor) => return Some(descriptor),
                TapTree::Branch(left, right) => {
                    self.stack.push(right);
                    self.stack.push(left);
                }
            }
        }
        None
    }
}

impl core::fmt::Display for TapTree {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut s = String::new();
        self.render(&mut s, &mut write_placeholder_key)
            .map_err(|_| core::fmt::Error)?;
        f.write_str(&s)
    }
}

impl core::fmt::Display for KeyOrigin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:08x}", self.fingerprint)?;
        for step in &self.derivation_path {
            write!(f, "/{}", step)?;
        }
        Ok(())
    }
}

impl core::convert::TryFrom<&str> for KeyOrigin {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        // parse a string in the form "76223a6e/48'/1'/0'/1'"
        // the key origin info between [] is optional and might not be present
        if s.is_empty() {
            return Err(ParseError::EmptyInput);
        }
        let parts: Vec<&str> = s.split('/').collect();
        if parts[0].len() != 8 {
            return Err(ParseError::InvalidLength);
        }
        let fingerprint = u32::from_str_radix(parts[0], 16).map_err(|_| ParseError::InvalidKey)?;
        let derivation_path = parts[1..]
            .iter()
            .map(|x| ChildNumber::from_str(x).map_err(|_| ParseError::InvalidKey))
            .collect::<Result<Vec<ChildNumber>, Self::Error>>()?;
        Ok(KeyOrigin {
            fingerprint,
            derivation_path,
        })
    }
}

impl core::fmt::Display for KeyInformation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.origin_info {
            Some(origin_info) => write!(f, "[{}]{}", origin_info, self.pubkey),
            None => write!(f, "{}", self.pubkey),
        }
    }
}

impl core::fmt::Display for KeyExpression {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.key_type {
            KeyExpressionType::PlainKey(key_index) => {
                if self.num1 == 0 && self.num2 == 1 {
                    write!(f, "@{}/**", key_index)
                } else {
                    write!(f, "@{}/<{};{}>/*", key_index, self.num1, self.num2)
                }
            }
            KeyExpressionType::Musig(key_indices) => {
                write!(f, "musig(")?;
                for (i, idx) in key_indices.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "@{}", idx)?;
                }
                if self.num1 == 0 && self.num2 == 1 {
                    write!(f, ")/**")
                } else {
                    write!(f, ")/<{};{}>/*", self.num1, self.num2)
                }
            }
        }
    }
}

impl TryFrom<&str> for KeyInformation {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if s.is_empty() {
            return Err(ParseError::EmptyInput);
        }
        let (origin_info, pubkey_pos) = if s.starts_with('[') {
            let end = s.find(']').ok_or(ParseError::InvalidKey)?;
            (Some(KeyOrigin::try_from(&s[1..end])?), end + 1)
        } else {
            (None, 0)
        };
        let pubkey = Xpub::from_str(&s[pubkey_pos..]).map_err(|_| ParseError::InvalidKey)?;
        Ok(KeyInformation {
            pubkey,
            origin_info,
        })
    }
}

pub trait ToDescriptor {
    fn to_descriptor(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<String, ParseError>;
}

// Return type for all hand-rolled parser functions: (remaining_input, parsed_value)
type ParseResult<'a, T> = Result<(&'a str, T), ParseError>;

// Parses a decimal u32 (no leading zeros unless "0"), value <= max.
fn parse_number_up_to(input: &str, max: u32) -> ParseResult<'_, u32> {
    if input.is_empty() || !input.starts_with(|c: char| c.is_ascii_digit()) {
        return Err(ParseError::InvalidSyntax);
    }
    // reject leading zeros on multi-digit numbers
    if input.starts_with('0') && input.len() > 1 && input.as_bytes()[1].is_ascii_digit() {
        return Err(ParseError::NumberOutOfRange);
    }
    let end = input
        .bytes()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(input.len());
    let num: u32 = input[..end]
        .parse()
        .map_err(|_| ParseError::NumberOutOfRange)?;
    if num > max {
        return Err(ParseError::NumberOutOfRange);
    }
    Ok((&input[end..], num))
}

// Entry-point: parse a complete descriptor template string.
fn parse_descriptor_template(input: &str) -> Result<DescriptorTemplate, ParseError> {
    let (rest, descriptor) = parse_descriptor(input, ParseContext::TopLevel, 0)?;
    if rest.is_empty() {
        Ok(descriptor)
    } else {
        Err(ParseError::TrailingInput)
    }
}

// Parses the derivation suffix: /** or /<num1;num2>/*
//
// `num1`/`num2` are plain, unhardened derivation indices (0..=2147483647): a
// trailing `'` is rejected, since these are the change/multipath steps of a key
// derived from an xpub, which cannot be hardened.
fn parse_derivation_suffix(input: &str) -> ParseResult<'_, (u32, u32)> {
    if !input.starts_with('/') {
        return Err(ParseError::InvalidSyntax);
    }
    let rest = &input[1..];

    if let Some(rest) = rest.strip_prefix("**") {
        Ok((rest, (0u32, 1u32)))
    } else if let Some(rest) = rest.strip_prefix('<') {
        let (rest, num1) = parse_number_up_to(rest, HARDENED_INDEX - 1)?;
        if !rest.starts_with(';') {
            return Err(ParseError::InvalidSyntax);
        }
        let (rest, num2) = parse_number_up_to(&rest[1..], HARDENED_INDEX - 1)?;
        if !rest.starts_with(">/*") {
            return Err(ParseError::InvalidSyntax);
        }
        // BIP-388: the two numbers in `/<NUM;NUM>/*` must be distinct.
        if num1 == num2 {
            return Err(ParseError::NonDistinctMultipath);
        }
        Ok((&rest[3..], (num1, num2)))
    } else {
        Err(ParseError::InvalidSyntax)
    }
}

// Parses a key expression: @N/** or @N/<num1;num2>/*
// When the context allows musig, also accepts: musig(@N1,@N2,...)/** or musig(@N1,@N2,...)/<num1;num2>/*
// musig() is only valid inside tr() (BIP-390).
fn parse_key_expression(input: &str, ctx: ParseContext) -> ParseResult<'_, KeyExpression> {
    if input.starts_with("musig(") {
        if !ctx.musig_allowed() {
            return Err(ParseError::InvalidScriptContext);
        }
        return parse_musig_key_expression(input);
    }
    if !input.starts_with('@') {
        return Err(ParseError::InvalidSyntax);
    }
    let (rest, key_index) = parse_number_up_to(&input[1..], u32::MAX)?;
    let (rest, (num1, num2)) = parse_derivation_suffix(rest)?;

    Ok((rest, KeyExpression::plain(key_index, num1, num2)))
}

// Parses a musig key expression: musig(@N1,@N2,...)/** or musig(@N1,@N2,...)/<num1;num2>/*
// Per BIP-390, all participant key indices must be distinct.
fn parse_musig_key_expression(input: &str) -> ParseResult<'_, KeyExpression> {
    let mut rest = &input[6..]; // skip "musig("
    let mut key_indices = Vec::new();
    loop {
        if !rest.starts_with('@') {
            return Err(ParseError::InvalidSyntax);
        }
        let (r, idx) = parse_number_up_to(&rest[1..], u32::MAX)?;
        if key_indices.contains(&idx) {
            return Err(ParseError::InvalidKey);
        }
        key_indices.push(idx);
        rest = r;
        if rest.starts_with(',') {
            rest = &rest[1..];
        } else {
            break;
        }
    }
    if key_indices.len() < 2 {
        return Err(ParseError::TooFewKeyExpressions);
    }
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    rest = &rest[1..]; // skip ')'
    let (rest, (num1, num2)) = parse_derivation_suffix(rest)?;

    Ok((rest, KeyExpression::musig(key_indices, num1, num2)))
}

// Parses a descriptor, optionally preceded by a wrapper prefix like "asc:".
//
// `depth` is the current recursion depth; it is incremented on every call and
// rejected if it exceeds [`MAX_PARSE_DEPTH`]. This bounds stack usage on
// untrusted input that nests descriptors arbitrarily deeply (e.g.
// `andor(0,0,andor(0,0,...))` or `tr(@0,{{{{...}}}})`). A chain of wrapper
// letters like `aaaa:0` does not grow recursion depth because wrappers are
// applied iteratively in this function, not by re-entry.
fn parse_descriptor(
    input: &str,
    ctx: ParseContext,
    depth: usize,
) -> ParseResult<'_, DescriptorTemplate> {
    if depth >= MAX_PARSE_DEPTH {
        return Err(ParseError::NestingTooDeep);
    }
    let depth = depth + 1;

    // A wrapper prefix is a run of ASCII alphabetic chars followed by ':'.
    // Fragment keywords are always followed by '(' instead, so no ambiguity.
    let alpha_end = input
        .bytes()
        .position(|b| !b.is_ascii_alphabetic())
        .unwrap_or(input.len());
    let (input, wrappers) = if alpha_end > 0 && input.as_bytes().get(alpha_end) == Some(&b':') {
        let wrappers = &input[..alpha_end];
        (&input[alpha_end + 1..], wrappers)
    } else {
        (input, "")
    };

    let (input, inner) = parse_inner_descriptor(input, ctx, depth)?;

    // Apply wrappers in reverse character order (rightmost char = outermost wrapper)
    let mut result = inner;
    for wrapper in wrappers.chars().rev() {
        result = match wrapper {
            'a' => DescriptorTemplate::A(Box::new(result)),
            's' => DescriptorTemplate::S(Box::new(result)),
            'c' => DescriptorTemplate::C(Box::new(result)),
            't' => DescriptorTemplate::T(Box::new(result)),
            'd' => DescriptorTemplate::D(Box::new(result)),
            'v' => DescriptorTemplate::V(Box::new(result)),
            'j' => DescriptorTemplate::J(Box::new(result)),
            'n' => DescriptorTemplate::N(Box::new(result)),
            'l' => DescriptorTemplate::L(Box::new(result)),
            'u' => DescriptorTemplate::U(Box::new(result)),
            _ => return Err(ParseError::InvalidSyntax),
        };
    }
    Ok((input, result))
}

fn parse_inner_descriptor(
    input: &str,
    ctx: ParseContext,
    depth: usize,
) -> ParseResult<'_, DescriptorTemplate> {
    // Longer names checked before shorter to avoid premature prefix matches.
    // Each `strip_prefix` consumes the keyword and its opening '(', so the
    // fragment helpers receive the input positioned at the first argument.
    if let Some(rest) = input.strip_prefix("sortedmulti_a(") {
        if !ctx.multi_a_allowed() {
            return Err(ParseError::InvalidScriptContext);
        }
        return parse_threshold_kp_fragment(
            rest,
            DescriptorTemplate::Sortedmulti_a,
            ctx,
            MAX_KEYS_MULTI_A,
        );
    }
    if let Some(rest) = input.strip_prefix("sortedmulti(") {
        if !ctx.multi_allowed() {
            return Err(ParseError::InvalidScriptContext);
        }
        return parse_threshold_kp_fragment(
            rest,
            DescriptorTemplate::Sortedmulti,
            ctx,
            MAX_KEYS_MULTI,
        );
    }
    if let Some(rest) = input.strip_prefix("multi_a(") {
        if !ctx.multi_a_allowed() {
            return Err(ParseError::InvalidScriptContext);
        }
        return parse_threshold_kp_fragment(
            rest,
            DescriptorTemplate::Multi_a,
            ctx,
            MAX_KEYS_MULTI_A,
        );
    }
    if let Some(rest) = input.strip_prefix("multi(") {
        if !ctx.multi_allowed() {
            return Err(ParseError::InvalidScriptContext);
        }
        return parse_threshold_kp_fragment(rest, DescriptorTemplate::Multi, ctx, MAX_KEYS_MULTI);
    }
    if input.starts_with("thresh(") {
        return parse_thresh(input, ctx, depth);
    }
    if let Some(input) = input.strip_prefix("wsh(") {
        if !ctx.wsh_allowed() {
            return Err(ParseError::InvalidScriptContext);
        }
        let inner_ctx = match ctx {
            ParseContext::TopLevel => ParseContext::Segwit,
            ParseContext::Legacy => ParseContext::WrappedSegwit,
            // `wsh_allowed` returns true only for `TopLevel`/`Legacy`; if a new
            // `ParseContext` variant is added in the future, default to rejecting
            // rather than panicking on hostile input.
            _ => return Err(ParseError::InvalidScriptContext),
        };

        let (rest, [script]) = parse_n_subscripts(input, inner_ctx, depth)?;
        return Ok((rest, DescriptorTemplate::Wsh(Box::new(script))));
    }
    if let Some(input) = input.strip_prefix("sh(") {
        if !ctx.sh_allowed() {
            return Err(ParseError::InvalidScriptContext);
        }
        let (rest, [script]) = parse_n_subscripts(input, ParseContext::Legacy, depth)?;
        return Ok((rest, DescriptorTemplate::Sh(Box::new(script))));
    }
    if let Some(rest) = input.strip_prefix("wpkh(") {
        if !ctx.wpkh_allowed() {
            return Err(ParseError::InvalidScriptContext);
        }
        return parse_kp_fragment(rest, DescriptorTemplate::Wpkh, ctx);
    }
    if let Some(rest) = input.strip_prefix("pkh(") {
        return parse_kp_fragment(rest, DescriptorTemplate::Pkh, ctx);
    }
    if input.starts_with("tr(") {
        if !ctx.tr_allowed() {
            return Err(ParseError::InvalidScriptContext);
        }
        return parse_tr(input, depth);
    }
    if let Some(rest) = input.strip_prefix("pk_k(") {
        return parse_kp_fragment(rest, DescriptorTemplate::Pk_k, ctx);
    }
    if let Some(rest) = input.strip_prefix("pk_h(") {
        return parse_kp_fragment(rest, DescriptorTemplate::Pk_h, ctx);
    }
    if let Some(rest) = input.strip_prefix("pk(") {
        return parse_kp_fragment(rest, DescriptorTemplate::Pk, ctx);
    }
    if let Some(rest) = input.strip_prefix("older(") {
        return parse_num_fragment(rest, MAX_OLDER_AFTER, DescriptorTemplate::Older);
    }
    if let Some(rest) = input.strip_prefix("after(") {
        return parse_num_fragment(rest, MAX_OLDER_AFTER, DescriptorTemplate::After);
    }
    if let Some(rest) = input.strip_prefix("sha256(") {
        return parse_hex32_fragment(rest, DescriptorTemplate::Sha256);
    }
    if let Some(rest) = input.strip_prefix("hash256(") {
        return parse_hex32_fragment(rest, DescriptorTemplate::Hash256);
    }
    if let Some(rest) = input.strip_prefix("ripemd160(") {
        return parse_hex20_fragment(rest, DescriptorTemplate::Ripemd160);
    }
    if let Some(rest) = input.strip_prefix("hash160(") {
        return parse_hex20_fragment(rest, DescriptorTemplate::Hash160);
    }
    if let Some(input) = input.strip_prefix("andor(") {
        let (rest, [x, y, z]) = parse_n_subscripts(input, ctx, depth)?;
        return Ok((
            rest,
            DescriptorTemplate::Andor(Box::new(x), Box::new(y), Box::new(z)),
        ));
    }
    if let Some(input) = input.strip_prefix("and_b(") {
        let (rest, [x, y]) = parse_n_subscripts(input, ctx, depth)?;
        return Ok((rest, DescriptorTemplate::And_b(Box::new(x), Box::new(y))));
    }
    if let Some(input) = input.strip_prefix("and_v(") {
        let (rest, [x, y]) = parse_n_subscripts(input, ctx, depth)?;
        return Ok((rest, DescriptorTemplate::And_v(Box::new(x), Box::new(y))));
    }
    if let Some(input) = input.strip_prefix("and_n(") {
        let (rest, [x, y]) = parse_n_subscripts(input, ctx, depth)?;
        return Ok((rest, DescriptorTemplate::And_n(Box::new(x), Box::new(y))));
    }
    if let Some(input) = input.strip_prefix("or_b(") {
        let (rest, [x, y]) = parse_n_subscripts(input, ctx, depth)?;
        return Ok((rest, DescriptorTemplate::Or_b(Box::new(x), Box::new(y))));
    }
    if let Some(input) = input.strip_prefix("or_c(") {
        let (rest, [x, y]) = parse_n_subscripts(input, ctx, depth)?;
        return Ok((rest, DescriptorTemplate::Or_c(Box::new(x), Box::new(y))));
    }
    if let Some(input) = input.strip_prefix("or_d(") {
        let (rest, [x, y]) = parse_n_subscripts(input, ctx, depth)?;
        return Ok((rest, DescriptorTemplate::Or_d(Box::new(x), Box::new(y))));
    }
    if let Some(input) = input.strip_prefix("or_i(") {
        let (rest, [x, y]) = parse_n_subscripts(input, ctx, depth)?;
        return Ok((rest, DescriptorTemplate::Or_i(Box::new(x), Box::new(y))));
    }
    // Simple terminals: bare "0" and "1"
    if let Some(rest) = input.strip_prefix('0') {
        return Ok((rest, DescriptorTemplate::Zero));
    }
    if let Some(rest) = input.strip_prefix('1') {
        return Ok((rest, DescriptorTemplate::One));
    }
    Err(ParseError::UnrecognizedFragment)
}

// Parses the body of a fragment that wraps a single key expression: `@...)`.
// `input` is positioned just after the fragment's opening '('.
fn parse_kp_fragment<'a>(
    input: &'a str,
    constructor: fn(KeyExpression) -> DescriptorTemplate,
    ctx: ParseContext,
) -> ParseResult<'a, DescriptorTemplate> {
    let (rest, kp) = parse_key_expression(input, ctx)?;
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    Ok((&rest[1..], constructor(kp)))
}

// Parses "n)" where n is a number <= max. `input` is positioned just after '('.
fn parse_num_fragment<'a>(
    input: &'a str,
    max: u32,
    constructor: fn(u32) -> DescriptorTemplate,
) -> ParseResult<'a, DescriptorTemplate> {
    let (rest, num) = parse_number_up_to(input, max)?;
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    Ok((&rest[1..], constructor(num)))
}

// Parses "<40 hex chars>)". `input` is positioned just after '('.
fn parse_hex20_fragment<'a>(
    input: &'a str,
    constructor: fn([u8; 20]) -> DescriptorTemplate,
) -> ParseResult<'a, DescriptorTemplate> {
    if input.len() < 40 {
        return Err(ParseError::InvalidLength);
    }
    let bytes = <[u8; 20]>::from_hex(&input[..40]).map_err(|_| ParseError::InvalidHex)?;
    let rest = &input[40..];
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    Ok((&rest[1..], constructor(bytes)))
}

// Parses "<64 hex chars>)". `input` is positioned just after '('.
fn parse_hex32_fragment<'a>(
    input: &'a str,
    constructor: fn([u8; 32]) -> DescriptorTemplate,
) -> ParseResult<'a, DescriptorTemplate> {
    if input.len() < 64 {
        return Err(ParseError::InvalidLength);
    }
    let bytes = <[u8; 32]>::from_hex(&input[..64]).map_err(|_| ParseError::InvalidHex)?;
    let rest = &input[64..];
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    Ok((&rest[1..], constructor(bytes)))
}

// Parses "threshold,<key1>,<key2>,...)". `input` is positioned just after '('.
fn parse_threshold_kp_fragment<'a>(
    input: &'a str,
    constructor: fn(u32, Vec<KeyExpression>) -> DescriptorTemplate,
    ctx: ParseContext,
    max_keys: usize,
) -> ParseResult<'a, DescriptorTemplate> {
    let (mut rest, threshold) = parse_number_up_to(input, u32::MAX)?;
    let mut keys: Vec<KeyExpression> = Vec::new();
    loop {
        if !rest.starts_with(',') {
            break;
        }
        if keys.len() >= max_keys {
            return Err(ParseError::TooManyKeys);
        }
        match parse_key_expression(&rest[1..], ctx) {
            Ok((r, kp)) => {
                keys.push(kp);
                rest = r;
            }
            // A hard script-context violation must propagate; only a "can't
            // parse another key here" error (`Err(_)`) ends the key list.
            Err(e @ ParseError::InvalidScriptContext) => return Err(e),
            Err(_) => break,
        }
    }
    if keys.len() < 2 {
        return Err(ParseError::TooFewKeyExpressions);
    }
    if threshold == 0 || (threshold as usize) > keys.len() {
        return Err(ParseError::InvalidMultisigQuorum);
    }
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    Ok((&rest[1..], constructor(threshold, keys)))
}

// Parses exactly `N` comma-separated sub-descriptors followed by ')'.
// Called after the opening '(' of the enclosing fragment has been consumed.
fn parse_n_subscripts<const N: usize>(
    input: &str,
    ctx: ParseContext,
    depth: usize,
) -> ParseResult<'_, [DescriptorTemplate; N]> {
    let mut rest = input;
    let mut scripts: Vec<DescriptorTemplate> = Vec::with_capacity(N);
    for i in 0..N {
        let (r, desc) = parse_descriptor(rest, ctx, depth)?;
        scripts.push(desc);
        rest = r;
        if i + 1 < N {
            if !rest.starts_with(',') {
                return Err(ParseError::InvalidSyntax);
            }
            rest = &rest[1..];
        }
    }
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    let array: [DescriptorTemplate; N] =
        scripts.try_into().expect("loop pushed exactly N elements");
    Ok((&rest[1..], array))
}

#[cfg(test)]
fn parse_wsh(input: &str) -> ParseResult<'_, DescriptorTemplate> {
    if !input.starts_with("wsh(") {
        return Err(ParseError::InvalidSyntax);
    }
    let (rest, [script]) = parse_n_subscripts(&input[4..], ParseContext::Segwit, 0)?;
    Ok((rest, DescriptorTemplate::Wsh(Box::new(script))))
}

#[cfg(test)]
fn parse_sortedmulti(input: &str) -> ParseResult<'_, DescriptorTemplate> {
    let rest = input
        .strip_prefix("sortedmulti(")
        .ok_or(ParseError::InvalidSyntax)?;
    // `sortedmulti` is only valid inside `sh`/`wsh`; use a segwit context so
    // this helper exercises the fragment as it would appear in a real policy.
    parse_threshold_kp_fragment(
        rest,
        DescriptorTemplate::Sortedmulti,
        ParseContext::Segwit,
        MAX_KEYS_MULTI,
    )
}

fn parse_thresh(
    input: &str,
    ctx: ParseContext,
    depth: usize,
) -> ParseResult<'_, DescriptorTemplate> {
    // input starts with "thresh("
    let (rest, k) = parse_number_up_to(&input[7..], u32::MAX)?;
    if !rest.starts_with(',') {
        return Err(ParseError::InvalidSyntax);
    }
    // parse first script (mandatory)
    let (mut rest, first) = parse_descriptor(&rest[1..], ctx, depth)?;
    let mut scripts = vec![first];
    loop {
        if !rest.starts_with(',') {
            break;
        }
        match parse_descriptor(&rest[1..], ctx, depth) {
            Ok((r, desc)) => {
                scripts.push(desc);
                rest = r;
            }
            // A hard nesting-limit error must propagate; only a "can't parse
            // another sub-script here" error (`Err(_)`) ends the list.
            Err(e @ ParseError::NestingTooDeep) => return Err(e),
            Err(_) => break,
        }
    }
    if k == 0 {
        return Err(ParseError::InvalidMultisigQuorum);
    }
    if (k as usize) > scripts.len() {
        return Err(ParseError::ThreshExceedsScripts);
    }
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    Ok((&rest[1..], DescriptorTemplate::Thresh(k, scripts)))
}

fn parse_tr(input: &str, depth: usize) -> ParseResult<'_, DescriptorTemplate> {
    // input starts with "tr("
    let (rest, key_placeholder) = parse_key_expression(&input[3..], ParseContext::Taproot)?;
    let (rest, tree) = if let Some(rest) = rest.strip_prefix(',') {
        let (rest, tree) = parse_tap_tree(rest, depth)?;
        (rest, Some(tree))
    } else {
        (rest, None)
    };
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    Ok((&rest[1..], DescriptorTemplate::Tr(key_placeholder, tree)))
}

fn parse_tap_tree(input: &str, depth: usize) -> ParseResult<'_, TapTree> {
    if depth >= MAX_PARSE_DEPTH {
        return Err(ParseError::NestingTooDeep);
    }
    let depth = depth + 1;
    if let Some(input) = input.strip_prefix('{') {
        let (rest, left) = parse_tap_tree(input, depth)?;
        if !rest.starts_with(',') {
            return Err(ParseError::InvalidSyntax);
        }
        let (rest, right) = parse_tap_tree(&rest[1..], depth)?;
        if !rest.starts_with('}') {
            return Err(ParseError::InvalidSyntax);
        }
        Ok((&rest[1..], TapTree::Branch(Box::new(left), Box::new(right))))
    } else {
        let (rest, desc) = parse_descriptor(input, ParseContext::Taproot, depth)?;
        Ok((rest, TapTree::Script(Box::new(desc))))
    }
}

impl FromStr for DescriptorTemplate {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parse_descriptor_template(input)
    }
}

impl core::fmt::Display for DescriptorTemplate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut s = String::new();
        self.render(&mut s, &mut write_placeholder_key)
            .map_err(|_| core::fmt::Error)?;
        f.write_str(&s)
    }
}

/// A BIP-388 wallet policy: a parsed [`DescriptorTemplate`] together with the
/// list of [`KeyInformation`] entries it references, and the original textual
/// template the policy was constructed from.
///
/// Once constructed, a `WalletPolicy` is immutable. Fields are private so the
/// parsed template cannot drift from the raw string used to compute the
/// registration HMAC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletPolicy {
    descriptor_template: DescriptorTemplate,
    key_information: Vec<KeyInformation>,
    descriptor_template_raw: String,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SegwitVersion {
    Legacy,
    SegwitV0,
    Taproot,
}

impl SegwitVersion {
    pub fn is_segwit(&self) -> bool {
        matches!(self, SegwitVersion::SegwitV0 | SegwitVersion::Taproot)
    }
}

/// Validates the BIP-388 "Additional rules" that go beyond template syntax:
///
/// * **B1** at least one key placeholder must be present;
/// * **B2** every referenced key index must resolve into `key_information`, and
///   the key vector must be fully used (a bijection with `{0, .., k-1}`). The
///   `@i` first-appearance *ordering* is a SHOULD in BIP-388 and is deliberately
///   **not** enforced, so out-of-order templates are accepted;
/// * **B3** the public keys in `key_information` must be pairwise distinct;
/// * **B4** if the same key placeholder is used with several `/<M;N>/*` suffixes,
///   the index sets `{M,N}` must be pairwise disjoint. Two `musig(...)`
///   placeholders count as the same key iff they have the same *set* of indices.
fn validate_policy(
    template: &DescriptorTemplate,
    key_information: &[KeyInformation],
) -> Result<(), ParseError> {
    use alloc::collections::{BTreeMap, BTreeSet};

    // Collect the placeholders once, in traversal order.
    let placeholders: Vec<&KeyExpression> = template.placeholders().map(|(kp, _)| kp).collect();

    // B1: a wallet policy must have at least one key placeholder.
    if placeholders.is_empty() {
        return Err(ParseError::NoKeyPlaceholders);
    }

    // B2: every referenced index must resolve to a key, and the vector must be
    // used exactly. Since every referenced index is checked to be `< k`, the set
    // of referenced indices equals `{0, .., k-1}` iff it has exactly `k` members.
    let k = key_information.len();
    let mut referenced: BTreeSet<u32> = BTreeSet::new();
    for kp in &placeholders {
        let indices: &[u32] = match &kp.key_type {
            KeyExpressionType::PlainKey(i) => core::slice::from_ref(i),
            KeyExpressionType::Musig(indices) => indices,
        };
        for &i in indices {
            if (i as usize) >= k {
                return Err(ParseError::InvalidKeyIndex);
            }
            referenced.insert(i);
        }
    }
    if referenced.len() != k {
        return Err(ParseError::KeyIndexCountMismatch);
    }

    // B3: the public keys must be pairwise distinct (compared as serialized
    // xpubs; the origin info is irrelevant to key identity).
    let mut seen_keys: BTreeSet<[u8; 78]> = BTreeSet::new();
    for key_info in key_information {
        if !seen_keys.insert(key_info.pubkey.encode()) {
            return Err(ParseError::DuplicateKey);
        }
    }

    // B4: multipath index sets for each key placeholder must be pairwise
    // disjoint across its occurrences.
    let mut used_per_key: BTreeMap<KeyExpressionType, BTreeSet<u32>> = BTreeMap::new();
    for kp in &placeholders {
        // Normalize musig groups so identity is the *set* of indices, regardless
        // of the order they were written in.
        let key = match &kp.key_type {
            KeyExpressionType::PlainKey(_) => kp.key_type.clone(),
            KeyExpressionType::Musig(indices) => {
                let mut sorted = indices.clone();
                sorted.sort_unstable();
                KeyExpressionType::Musig(sorted)
            }
        };
        let used = used_per_key.entry(key).or_default();
        // A1 guarantees `num1 != num2` within one expression, so a clash here
        // means two occurrences of this placeholder share a multipath index.
        if !used.insert(kp.num1) || !used.insert(kp.num2) {
            return Err(ParseError::OverlappingMultipath);
        }
    }

    Ok(())
}

impl WalletPolicy {
    pub fn new(
        descriptor_template_str: &str,
        key_information: Vec<KeyInformation>,
    ) -> Result<Self, ParseError> {
        let descriptor_template = DescriptorTemplate::from_str(descriptor_template_str)?;

        validate_policy(&descriptor_template, &key_information)?;

        Ok(Self {
            descriptor_template,
            key_information,
            descriptor_template_raw: String::from(descriptor_template_str),
        })
    }

    /// The parsed descriptor template AST.
    pub fn descriptor_template(&self) -> &DescriptorTemplate {
        &self.descriptor_template
    }

    /// The list of key information entries referenced by the template's
    /// `@i` placeholders.
    pub fn key_information(&self) -> &[KeyInformation] {
        &self.key_information
    }

    /// The exact textual template that was passed to [`WalletPolicy::new`].
    /// This string is what gets HMACed during account registration, so it is
    /// preserved byte-for-byte rather than re-derived via `Display`.
    pub fn descriptor_template_raw(&self) -> &str {
        &self.descriptor_template_raw
    }

    pub fn serialize(&self) -> Vec<u8> {
        // `consensus_encode` only fails when its writer fails. Writing to a `Vec`
        // is infallible, so all `expect`s below are unreachable in practice.
        let mut result = Vec::<u8>::new();

        let len = VarInt(self.descriptor_template_raw().len() as u64);
        len.consensus_encode(&mut result)
            .expect("writing to Vec is infallible");
        result.extend_from_slice(self.descriptor_template_raw().as_bytes());

        // number of keys
        VarInt(self.key_information.len() as u64)
            .consensus_encode(&mut result)
            .expect("writing to Vec is infallible");
        for key_info in &self.key_information {
            // serialize key information
            match &key_info.origin_info {
                None => {
                    result.push(0);
                }
                Some(k) => {
                    result.push(1);
                    result.extend_from_slice(&k.fingerprint.to_be_bytes());
                    VarInt(k.derivation_path.len() as u64)
                        .consensus_encode(&mut result)
                        .expect("writing to Vec is infallible");
                    for step in k.derivation_path.iter() {
                        result.extend_from_slice(&u32::from(*step).to_le_bytes());
                    }
                }
            }
            // serialize pubkey
            result.extend_from_slice(&key_info.pubkey.encode());
        }

        result
    }

    pub fn deserialize<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        // Deserialize descriptor template. Reject lengths exceeding
        // `MAX_SERIALIZED_DESCRIPTORTEMPLATE_LEN` before allocating to prevent a hostile
        // `VarInt` from triggering an unbounded allocation.
        let VarInt(desc_len) = VarInt::consensus_decode(r)?;
        if desc_len > MAX_SERIALIZED_DESCRIPTORTEMPLATE_LEN as u64 {
            return Err(encode::Error::ParseFailed("Descriptor template too long"));
        }
        let mut desc_bytes = vec![0u8; desc_len as usize];
        r.read_exact(&mut desc_bytes)?;
        let descriptor_template_str = String::from_utf8(desc_bytes)
            .map_err(|_| encode::Error::ParseFailed("Invalid UTF-8 in descriptor"))?;

        // Deserialize key_information vector. Same bound check before allocating.
        let VarInt(key_count) = VarInt::consensus_decode(r)?;
        if key_count > MAX_SERIALIZED_KEY_COUNT as u64 {
            return Err(encode::Error::ParseFailed("Too many keys"));
        }
        let mut key_information = Vec::with_capacity(key_count as usize);
        for _ in 0..key_count {
            let mut flag = [0u8; 1];
            r.read_exact(&mut flag)?;
            let origin_info = match flag[0] {
                0 => None,
                1 => {
                    let mut fp_buf = [0; 4];
                    r.read_exact(&mut fp_buf)?;
                    let fingerprint = u32::from_be_bytes(fp_buf);
                    let VarInt(dp_len) = VarInt::consensus_decode(r)?;
                    // keys used in wallet policies must leave space for the final change/address_index derivation steps
                    if dp_len > (MAX_BIP32_DERIVATION_PATH_LEN - 2) as u64 {
                        return Err(encode::Error::ParseFailed("Derivation path too long"));
                    }
                    let mut derivation_path = Vec::with_capacity(dp_len as usize);
                    for _ in 0..dp_len {
                        let mut step_bytes = [0u8; 4];
                        r.read_exact(&mut step_bytes)?;
                        derivation_path.push(ChildNumber::from(u32::from_le_bytes(step_bytes)));
                    }
                    Some(KeyOrigin {
                        fingerprint,
                        derivation_path,
                    })
                }
                _ => {
                    return Err(encode::Error::ParseFailed("Invalid key information flag"));
                }
            };
            // Deserialize pubkey.
            let mut xpub_bytes = vec![0u8; 78];
            r.read_exact(&mut xpub_bytes)?;

            key_information.push(KeyInformation {
                origin_info,
                pubkey: Xpub::decode(&xpub_bytes)
                    .map_err(|_| encode::Error::ParseFailed("Invalid xpub"))?,
            });
        }

        // test that the stream is indeed exhausted
        let mut buf = [0u8; 1];
        if r.read(&mut buf)? != 0 {
            return Err(encode::Error::ParseFailed(
                "Extra data after deserializing WalletPolicy",
            ));
        }

        WalletPolicy::new(&descriptor_template_str, key_information).map_err(|_| {
            encode::Error::ParseFailed("Invalid descriptor template or key information")
        })
    }

    pub fn get_segwit_version(&self) -> Result<SegwitVersion, ParseError> {
        match &self.descriptor_template {
            DescriptorTemplate::Tr(_, _) => Ok(SegwitVersion::Taproot),
            DescriptorTemplate::Pkh(_) => Ok(SegwitVersion::Legacy),
            DescriptorTemplate::Wpkh(_) | DescriptorTemplate::Wsh(_) => Ok(SegwitVersion::SegwitV0),
            DescriptorTemplate::Sh(inner) => match inner.as_ref() {
                DescriptorTemplate::Wpkh(_) | DescriptorTemplate::Wsh(_) => {
                    Ok(SegwitVersion::SegwitV0)
                }
                _ => Ok(SegwitVersion::Legacy),
            },
            _ => Err(ParseError::InvalidTopLevelPolicy),
        }
    }
}

fn write_key_expression(
    w: &mut String,
    key_information: &[KeyInformation],
    kp: &KeyExpression,
    is_change: bool,
    address_index: u32,
) -> Result<(), ParseError> {
    use core::fmt::Write;
    let change_step = if is_change { kp.num2 } else { kp.num1 };
    match &kp.key_type {
        KeyExpressionType::PlainKey(key_index) => {
            let key_info = key_information
                .get(*key_index as usize)
                .ok_or(ParseError::InvalidKeyIndex)?;
            write!(w, "{}/{}/{}", key_info, change_step, address_index)
                .map_err(|_| ParseError::FormatError)
        }
        KeyExpressionType::Musig(key_indices) => {
            w.push_str("musig(");
            for (i, key_index) in key_indices.iter().enumerate() {
                if i > 0 {
                    w.push(',');
                }
                let key_info = key_information
                    .get(*key_index as usize)
                    .ok_or(ParseError::InvalidKeyIndex)?;
                write!(w, "{}", key_info).map_err(|_| ParseError::FormatError)?;
            }
            write!(w, ")/{}/{}", change_step, address_index).map_err(|_| ParseError::FormatError)
        }
    }
}

// Writes a key expression in template form: the `@N/**` (or `musig(@N,...)`)
// placeholder, exactly as `KeyExpression`'s `Display` renders it. This is the
// key writer used by the `Display` impls.
fn write_placeholder_key(w: &mut String, kp: &KeyExpression) -> Result<(), ParseError> {
    use core::fmt::Write;
    write!(w, "{}", kp).map_err(|_| ParseError::FormatError)
}

// Writes a comma-separated list of key expressions, formatting each with `write_key`.
fn write_key_list(
    w: &mut String,
    kps: &[KeyExpression],
    write_key: &mut impl FnMut(&mut String, &KeyExpression) -> Result<(), ParseError>,
) -> Result<(), ParseError> {
    for (i, kp) in kps.iter().enumerate() {
        if i > 0 {
            w.push(',');
        }
        write_key(w, kp)?;
    }
    Ok(())
}

// Writes a single-character wrapper prefix and its inner fragment, inserting a
// ':' only when the inner fragment is not itself a wrapper (the `asc:` vs `a`
// grammar).
fn write_wrapper(
    w: &mut String,
    ch: char,
    inner: &DescriptorTemplate,
    write_key: &mut impl FnMut(&mut String, &KeyExpression) -> Result<(), ParseError>,
) -> Result<(), ParseError> {
    w.push(ch);
    if !inner.is_wrapper() {
        w.push(':');
    }
    inner.render(w, write_key)
}

impl TapTree {
    // Renders this tap-tree to `w`, delegating each key placeholder to `write_key`.
    fn render(
        &self,
        w: &mut String,
        write_key: &mut impl FnMut(&mut String, &KeyExpression) -> Result<(), ParseError>,
    ) -> Result<(), ParseError> {
        match self {
            TapTree::Script(desc) => desc.render(w, write_key),
            TapTree::Branch(left, right) => {
                w.push('{');
                left.render(w, write_key)?;
                w.push(',');
                right.render(w, write_key)?;
                w.push('}');
                Ok(())
            }
        }
    }
}

impl DescriptorTemplate {
    /// Renders this template to `w`. The structure (keywords, parentheses,
    /// separators, wrappers) is written here; the formatting of each key
    /// placeholder is delegated to `write_key`. Both the template form
    /// (`Display`, via [`write_placeholder_key`]) and the concrete-descriptor
    /// form (`ToDescriptor`, via [`write_key_expression`]) go through this
    /// single renderer so the two can never drift apart.
    fn render(
        &self,
        w: &mut String,
        write_key: &mut impl FnMut(&mut String, &KeyExpression) -> Result<(), ParseError>,
    ) -> Result<(), ParseError> {
        use core::fmt::Write;

        match self {
            DescriptorTemplate::Sh(inner) => {
                w.push_str("sh(");
                inner.render(w, write_key)?;
                w.push(')');
            }
            DescriptorTemplate::Wsh(inner) => {
                w.push_str("wsh(");
                inner.render(w, write_key)?;
                w.push(')');
            }
            DescriptorTemplate::Pkh(kp) => {
                w.push_str("pkh(");
                write_key(w, kp)?;
                w.push(')');
            }
            DescriptorTemplate::Wpkh(kp) => {
                w.push_str("wpkh(");
                write_key(w, kp)?;
                w.push(')');
            }
            DescriptorTemplate::Sortedmulti(threshold, kps) => {
                write!(w, "sortedmulti({},", threshold).map_err(|_| ParseError::FormatError)?;
                write_key_list(w, kps, write_key)?;
                w.push(')');
            }
            DescriptorTemplate::Sortedmulti_a(threshold, kps) => {
                write!(w, "sortedmulti_a({},", threshold).map_err(|_| ParseError::FormatError)?;
                write_key_list(w, kps, write_key)?;
                w.push(')');
            }
            DescriptorTemplate::Tr(kp, tap_tree) => {
                w.push_str("tr(");
                write_key(w, kp)?;
                if let Some(tree) = tap_tree {
                    w.push(',');
                    tree.render(w, write_key)?;
                }
                w.push(')');
            }
            DescriptorTemplate::Zero => w.push('0'),
            DescriptorTemplate::One => w.push('1'),
            DescriptorTemplate::Pk(kp) => {
                w.push_str("pk(");
                write_key(w, kp)?;
                w.push(')');
            }
            DescriptorTemplate::Pk_k(kp) => {
                w.push_str("pk_k(");
                write_key(w, kp)?;
                w.push(')');
            }
            DescriptorTemplate::Pk_h(kp) => {
                w.push_str("pk_h(");
                write_key(w, kp)?;
                w.push(')');
            }
            DescriptorTemplate::Older(n) => {
                write!(w, "older({})", n).map_err(|_| ParseError::FormatError)?;
            }
            DescriptorTemplate::After(n) => {
                write!(w, "after({})", n).map_err(|_| ParseError::FormatError)?;
            }
            DescriptorTemplate::Sha256(hash) => {
                w.push_str("sha256(");
                w.push_str(&hex::encode(hash));
                w.push(')');
            }
            DescriptorTemplate::Ripemd160(hash) => {
                w.push_str("ripemd160(");
                w.push_str(&hex::encode(hash));
                w.push(')');
            }
            DescriptorTemplate::Hash256(hash) => {
                w.push_str("hash256(");
                w.push_str(&hex::encode(hash));
                w.push(')');
            }
            DescriptorTemplate::Hash160(hash) => {
                w.push_str("hash160(");
                w.push_str(&hex::encode(hash));
                w.push(')');
            }
            DescriptorTemplate::Andor(x, y, z) => {
                w.push_str("andor(");
                x.render(w, write_key)?;
                w.push(',');
                y.render(w, write_key)?;
                w.push(',');
                z.render(w, write_key)?;
                w.push(')');
            }
            DescriptorTemplate::And_v(x, y) => {
                w.push_str("and_v(");
                x.render(w, write_key)?;
                w.push(',');
                y.render(w, write_key)?;
                w.push(')');
            }
            DescriptorTemplate::And_b(x, y) => {
                w.push_str("and_b(");
                x.render(w, write_key)?;
                w.push(',');
                y.render(w, write_key)?;
                w.push(')');
            }
            DescriptorTemplate::And_n(x, y) => {
                w.push_str("and_n(");
                x.render(w, write_key)?;
                w.push(',');
                y.render(w, write_key)?;
                w.push(')');
            }
            DescriptorTemplate::Or_b(x, z) => {
                w.push_str("or_b(");
                x.render(w, write_key)?;
                w.push(',');
                z.render(w, write_key)?;
                w.push(')');
            }
            DescriptorTemplate::Or_c(x, z) => {
                w.push_str("or_c(");
                x.render(w, write_key)?;
                w.push(',');
                z.render(w, write_key)?;
                w.push(')');
            }
            DescriptorTemplate::Or_d(x, z) => {
                w.push_str("or_d(");
                x.render(w, write_key)?;
                w.push(',');
                z.render(w, write_key)?;
                w.push(')');
            }
            DescriptorTemplate::Or_i(x, z) => {
                w.push_str("or_i(");
                x.render(w, write_key)?;
                w.push(',');
                z.render(w, write_key)?;
                w.push(')');
            }
            DescriptorTemplate::Thresh(k, sub_templates) => {
                write!(w, "thresh({}", k).map_err(|_| ParseError::FormatError)?;
                for template in sub_templates {
                    w.push(',');
                    template.render(w, write_key)?;
                }
                w.push(')');
            }
            DescriptorTemplate::Multi(threshold, kps) => {
                write!(w, "multi({},", threshold).map_err(|_| ParseError::FormatError)?;
                write_key_list(w, kps, write_key)?;
                w.push(')');
            }
            DescriptorTemplate::Multi_a(threshold, kps) => {
                write!(w, "multi_a({},", threshold).map_err(|_| ParseError::FormatError)?;
                write_key_list(w, kps, write_key)?;
                w.push(')');
            }
            DescriptorTemplate::A(inner) => write_wrapper(w, 'a', inner, write_key)?,
            DescriptorTemplate::S(inner) => write_wrapper(w, 's', inner, write_key)?,
            DescriptorTemplate::C(inner) => write_wrapper(w, 'c', inner, write_key)?,
            DescriptorTemplate::T(inner) => write_wrapper(w, 't', inner, write_key)?,
            DescriptorTemplate::D(inner) => write_wrapper(w, 'd', inner, write_key)?,
            DescriptorTemplate::V(inner) => write_wrapper(w, 'v', inner, write_key)?,
            DescriptorTemplate::J(inner) => write_wrapper(w, 'j', inner, write_key)?,
            DescriptorTemplate::N(inner) => write_wrapper(w, 'n', inner, write_key)?,
            DescriptorTemplate::L(inner) => write_wrapper(w, 'l', inner, write_key)?,
            DescriptorTemplate::U(inner) => write_wrapper(w, 'u', inner, write_key)?,
        }
        Ok(())
    }
}

impl ToDescriptor for TapTree {
    fn to_descriptor(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<String, ParseError> {
        let mut result = String::new();
        self.render(&mut result, &mut |w, kp| {
            write_key_expression(w, key_information, kp, is_change, address_index)
        })?;
        Ok(result)
    }
}

impl ToDescriptor for DescriptorTemplate {
    fn to_descriptor(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<String, ParseError> {
        let mut result = String::new();
        self.render(&mut result, &mut |w, kp| {
            write_key_expression(w, key_information, kp, is_change, address_index)
        })?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: u32 = HARDENED_INDEX;

    fn make_key_origin_info(fpr: u32, der_path: Vec<u32>) -> KeyOrigin {
        KeyOrigin {
            fingerprint: fpr,
            derivation_path: der_path.into_iter().map(ChildNumber::from).collect(),
        }
    }

    fn koi(key_origin_str: &str) -> KeyInformation {
        KeyInformation::try_from(key_origin_str).unwrap()
    }

    // Three distinct valid xpubs used by the wallet-policy validation tests.
    const XPUB_A: &str = "tpubDE7NQymr4AFtcJXi9TaWZtrhAdy8QyKmT4U6b9qYByAxCzoyMJ8zw5d8xVLVpbTRAEqP8pVUxjLE2vDt1rSFjaiS8DSz1QcNZ8D1qxUMx1g";
    const XPUB_B: &str = "tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY";
    const XPUB_C: &str = "tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P";

    // `n` distinct KeyInformation entries (n <= 3) for policies that reference
    // exactly that many keys.
    fn distinct_keys(n: usize) -> Vec<KeyInformation> {
        [XPUB_A, XPUB_B, XPUB_C][..n]
            .iter()
            .map(|s| koi(s))
            .collect()
    }

    #[test]
    fn test_parse_key_origin() {
        let test_cases_success = vec![
            (
                "012345af/0'/1'/3",
                make_key_origin_info(0x012345af, vec![H, 1 + H, 3]),
            ),
            (
                "012345af/2147483647'/1'/3/6/7/42/12/54/23/56/89",
                make_key_origin_info(
                    0x012345af,
                    vec![2147483647 + H, 1 + H, 3, 6, 7, 42, 12, 54, 23, 56, 89],
                ),
            ),
            ("012345af", make_key_origin_info(0x012345af, vec![])),
        ];

        for (input, expected) in test_cases_success {
            assert_eq!(KeyOrigin::try_from(input), Ok(expected));
        }

        let test_cases_err = vec![
            "[01234567/0'/1'/3]",
            "0123456/0'/1'/3",
            "012345678/0'/1'/3",
            "012345ag/0'/1'/2147483648",
        ];

        for input in test_cases_err {
            assert!(KeyOrigin::try_from(input).is_err());
        }
    }

    #[test]
    fn test_parse_key_expression() {
        let test_cases_success = vec![
            ("@0/**", KeyExpression::plain(0, 0, 1)),
            ("@4294967295/**", KeyExpression::plain(4294967295, 0, 1)), // u32::MAX
            ("@1/<0;1>/*", KeyExpression::plain(1, 0, 1)),
            ("@2/<3;4>/*", KeyExpression::plain(2, 3, 4)),
            ("@3/<1;9>/*", KeyExpression::plain(3, 1, 9)),
        ];

        for (input, expected) in test_cases_success {
            let result = parse_key_expression(input, ParseContext::TopLevel);
            assert_eq!(result, Ok(("", expected)));
        }

        let test_cases_err = vec![
            "@0",
            "@0**",
            "@a/**",
            "@0/*",
            "@0/<0;1>",       // missing /*
            "@0/<0,1>/*",     // , instead of ;
            "@4294967296/**", // too large
            "0/**",
            "@0/<0';1>/*",         // hardened first multipath index
            "@0/<0;1'>/*",         // hardened second multipath index
            "@0/<2147483648;1>/*", // first multipath index out of range
            "@0/<0;2147483648>/*", // second multipath index out of range
        ];

        for input in test_cases_err {
            assert!(parse_key_expression(input, ParseContext::TopLevel).is_err());
        }
    }

    #[test]
    fn test_parse_sortedmulti() {
        let input = "sortedmulti(2,@0/**,@1/**)";
        let expected = Ok((
            "",
            DescriptorTemplate::Sortedmulti(
                2,
                vec![KeyExpression::plain(0, 0, 1), KeyExpression::plain(1, 0, 1)],
            ),
        ));
        assert_eq!(parse_sortedmulti(input), expected);
    }

    #[test]
    fn test_parse_wsh_sortedmulti() {
        let input = "wsh(sortedmulti(2,@0/**,@1/**))";
        let expected = Ok((
            "",
            DescriptorTemplate::Wsh(Box::new(DescriptorTemplate::Sortedmulti(
                2,
                vec![KeyExpression::plain(0, 0, 1), KeyExpression::plain(1, 0, 1)],
            ))),
        ));
        assert_eq!(parse_wsh(input), expected);
    }

    #[test]
    fn test_parse_tr() {
        let input = "tr(@0/**)";
        let expected = Ok((
            "",
            DescriptorTemplate::Tr(KeyExpression::plain(0, 0, 1), None),
        ));
        assert_eq!(parse_tr(input, 0), expected);

        let input = "tr(@0/**,pkh(@1/**))";
        let expected = Ok((
            "",
            DescriptorTemplate::Tr(
                KeyExpression::plain(0, 0, 1),
                Some(TapTree::Script(Box::new(DescriptorTemplate::Pkh(
                    KeyExpression::plain(1, 0, 1),
                )))),
            ),
        ));
        assert_eq!(parse_tr(input, 0), expected);

        let input = "tr(@0/<2;1>/*,{pkh(@1/<2;7>/*),pk(@2/**)})";
        let expected = Ok((
            "",
            DescriptorTemplate::Tr(
                KeyExpression::plain(0, 2, 1),
                Some(TapTree::Branch(
                    Box::new(TapTree::Script(Box::new(DescriptorTemplate::Pkh(
                        KeyExpression::plain(1, 2, 7),
                    )))),
                    Box::new(TapTree::Script(Box::new(DescriptorTemplate::Pk(
                        KeyExpression::plain(2, 0, 1),
                    )))),
                )),
            ),
        ));
        assert_eq!(parse_tr(input, 0), expected);

        // failure cases
        assert!(parse_tr("tr(@0/**,)", 0).is_err());
        assert!(parse_tr("tr(pkh(@0/**))", 0).is_err());
        assert!(parse_tr("tr(@0))", 0).is_err());
        assert!(parse_tr("tr(@0/*))", 0).is_err());
        assert!(parse_tr("tr(@0/*/0)", 0).is_err());
    }

    #[test]
    fn test_parse_valid_descriptor_templates() {
        assert!(parse_descriptor("sln:older(12960)", ParseContext::TopLevel, 0).is_ok());
        assert!(parse_thresh(
            "thresh(3,pk(@0/**),s:pk(@1/**),s:pk(@2/**),sln:older(12960))",
            ParseContext::TopLevel,
            0,
        )
        .is_ok());

        let test_cases = vec![
            "wsh(sortedmulti(2,@0/**,@1/**))",
            "sh(wsh(sortedmulti(2,@0/**,@1/**)))",
            "wsh(c:pk_k(@0/**))",
            "wsh(or_d(pk(@0/**),pkh(@1/**)))",
            "wsh(thresh(3,pk(@0/**),s:pk(@1/**),s:pk(@2/**),sln:older(12960)))",
        ];

        for input in test_cases {
            let result = parse_descriptor_template(input);
            assert!(result.is_ok())
        }
    }

    #[test]
    fn test_wallet_policy() {
        let wallet = WalletPolicy::new(
            "sh(wsh(sortedmulti(2,@0/**,@1/**)))",
            vec![
                koi("[76223a6e/48'/1'/0'/1']tpubDE7NQymr4AFtcJXi9TaWZtrhAdy8QyKmT4U6b9qYByAxCzoyMJ8zw5d8xVLVpbTRAEqP8pVUxjLE2vDt1rSFjaiS8DSz1QcNZ8D1qxUMx1g"),
                koi("[f5acc2fd/48'/1'/0'/1']tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY"),
            ]
        );

        assert!(wallet.is_ok());
    }

    #[test]
    fn test_descriptortemplate_placeholders_iterator() {
        fn format_kp(kp: &KeyExpression) -> String {
            let key_index = kp.plain_key_index().expect("expected plain key in test");
            format!("@{}/<{};{}>/*", key_index, kp.num1, kp.num2)
        }

        struct TestCase {
            descriptor: &'static str,
            expected: Vec<&'static str>,
        }
        impl TestCase {
            fn new(descriptor: &'static str, expected: &[&'static str]) -> Self {
                Self {
                    descriptor,
                    expected: Vec::from(expected),
                }
            }
        }

        // Define a list of test cases
        let test_cases = vec![
            TestCase::new("0", &[]),
            TestCase::new("after(12345)", &[]),
            TestCase::new("pkh(@0/**)", &["@0/<0;1>/*"]),
            TestCase::new("wpkh(@0/<11;67>/*)", &["@0/<11;67>/*"]),
            TestCase::new("tr(@0/**)", &["@0/<0;1>/*"]),
            TestCase::new(
                "wsh(or_i(and_v(v:pkh(@4/<3;7>/*),older(65535)),or_d(multi(2,@0/**,@3/**),and_v(v:thresh(1,pkh(@5/<99;101>/*),a:pkh(@1/**)),older(64231)))))",
                &["@4/<3;7>/*", "@0/<0;1>/*", "@3/<0;1>/*", "@5/<99;101>/*", "@1/<0;1>/*"]
            ),
            TestCase::new(
                "tr(@0/**,{sortedmulti_a(1,@1/**,@2/**),or_b(pk(@3/**),s:pk(@4/**))})",
                &["@0/<0;1>/*", "@1/<0;1>/*", "@2/<0;1>/*", "@3/<0;1>/*", "@4/<0;1>/*"]
            ),
            TestCase::new(
                "tr(@0/**,{{{sortedmulti_a(1,@1/**,@2/**,@3/**,@4/**,@5/**),multi_a(2,@6/**,@7/**,@8/**)},{multi_a(2,@9/**,@10/**,@11/**,@12/**),pk(@13/**)}},{{multi_a(2,@14/**,@15/**),multi_a(3,@16/**,@17/**,@18/**)},{multi_a(2,@19/**,@20/**),pk(@21/**)}}})",
                &["@0/<0;1>/*", "@1/<0;1>/*", "@2/<0;1>/*", "@3/<0;1>/*", "@4/<0;1>/*", "@5/<0;1>/*", "@6/<0;1>/*", "@7/<0;1>/*", "@8/<0;1>/*", "@9/<0;1>/*", "@10/<0;1>/*", "@11/<0;1>/*", "@12/<0;1>/*", "@13/<0;1>/*", "@14/<0;1>/*", "@15/<0;1>/*", "@16/<0;1>/*", "@17/<0;1>/*", "@18/<0;1>/*", "@19/<0;1>/*", "@20/<0;1>/*", "@21/<0;1>/*"]
            ),
        ];

        for case in test_cases {
            let desc = DescriptorTemplate::from_str(case.descriptor).unwrap();
            let iter = DescriptorTemplateIter::from(&desc);
            let results: Vec<_> = iter.map(|(k, _)| format_kp(k)).collect();

            assert_eq!(results, case.expected);
        }
    }

    #[test]
    fn test_display_roundtrip() {
        let cases = vec![
            "0",
            "1",
            "pkh(@0/**)",
            "wpkh(@0/**)",
            "wpkh(@0/<11;67>/*)",
            "wsh(sortedmulti(2,@0/**,@1/**))",
            "sh(wsh(sortedmulti(2,@0/**,@1/**)))",
            "wsh(c:pk_k(@0/**))",
            "wsh(or_d(pk(@0/**),pkh(@1/**)))",
            "wsh(thresh(3,pk(@0/**),s:pk(@1/**),s:pk(@2/**),sln:older(12960)))",
            "sln:older(12960)",
            "tr(@0/**)",
            "tr(@0/**,pkh(@1/**))",
            "tr(@0/<2;1>/*,{pkh(@1/<2;7>/*),pk(@2/**)})",
            "after(12345)",
            "older(65535)",
            "sha256(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)",
            "ripemd160(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)",
            "hash256(bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)",
            "hash160(bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)",
            "wsh(andor(pk(@0/**),older(1),pk(@1/**)))",
            "wsh(or_i(and_v(v:pkh(@4/<3;7>/*),older(65535)),or_d(multi(2,@0/**,@3/**),and_v(v:thresh(1,pkh(@5/<99;101>/*),a:pkh(@1/**)),older(64231)))))",
            "tr(@0/**,{sortedmulti_a(1,@1/**,@2/**),or_b(pk(@3/**),s:pk(@4/**))})",
        ];

        for s in cases {
            let parsed = DescriptorTemplate::from_str(s)
                .unwrap_or_else(|e| panic!("parse failed for {:?}: {:?}", s, e));
            let displayed = parsed.to_string();
            assert_eq!(displayed, s, "roundtrip failed for {:?}", s);
        }
    }

    #[test]
    fn test_musig_inside_tr_parses() {
        // musig() as the internal key of tr()
        let result = DescriptorTemplate::from_str("tr(musig(@0,@1)/**)");
        assert!(
            result.is_ok(),
            "musig as tr internal key should parse: {:?}",
            result
        );

        // musig() inside a tr() taptree leaf
        let result = DescriptorTemplate::from_str("tr(@0/**,pk(musig(@1,@2)/**))");
        assert!(
            result.is_ok(),
            "musig inside tr taptree should parse: {:?}",
            result
        );

        // musig() with more than two keys
        let result = DescriptorTemplate::from_str("tr(musig(@0,@1,@2)/**)");
        assert!(
            result.is_ok(),
            "musig with 3 keys should parse: {:?}",
            result
        );

        // musig() with <num1;num2>/* derivation
        let result = DescriptorTemplate::from_str("tr(musig(@0,@1)/<3;4>/*)");
        assert!(
            result.is_ok(),
            "musig with custom derivation should parse: {:?}",
            result
        );
    }

    #[test]
    fn test_musig_outside_tr_rejected() {
        // musig() inside wpkh() should fail
        assert_eq!(
            DescriptorTemplate::from_str("wpkh(musig(@0,@1)/**)"),
            Err(ParseError::InvalidScriptContext)
        );

        // musig() inside pkh() should fail
        assert_eq!(
            DescriptorTemplate::from_str("pkh(musig(@0,@1)/**)"),
            Err(ParseError::InvalidScriptContext)
        );

        // musig() inside wsh(sortedmulti()) should fail
        assert_eq!(
            DescriptorTemplate::from_str("wsh(sortedmulti(2,musig(@0,@1)/**,@2/**))"),
            Err(ParseError::InvalidScriptContext)
        );

        // musig() inside sh() should fail
        assert_eq!(
            DescriptorTemplate::from_str("sh(pk(musig(@0,@1)/**))"),
            Err(ParseError::InvalidScriptContext)
        );

        // musig() inside wsh(pk()) should fail
        assert_eq!(
            DescriptorTemplate::from_str("wsh(pk(musig(@0,@1)/**))"),
            Err(ParseError::InvalidScriptContext)
        );
    }

    #[test]
    fn test_musig_nested_not_allowed() {
        // musig() inside musig() is not valid because musig() arguments
        // must be plain @N key references, not nested key expressions
        assert!(
            DescriptorTemplate::from_str("tr(musig(musig(@0,@1),@2)/**)").is_err(),
            "nested musig should not parse"
        );
    }

    #[test]
    fn test_musig_display_roundtrip() {
        let cases = vec![
            "tr(musig(@0,@1)/**)",
            "tr(musig(@0,@1)/<3;4>/*)",
            "tr(musig(@0,@1,@2)/**)",
            "tr(@0/**,pk(musig(@1,@2)/**))",
        ];
        for s in cases {
            let parsed = DescriptorTemplate::from_str(s)
                .unwrap_or_else(|e| panic!("parse failed for {:?}: {:?}", s, e));
            let displayed = parsed.to_string();
            assert_eq!(displayed, s, "roundtrip failed for {:?}", s);
        }
    }

    #[test]
    fn test_sh_only_allowed_top_level() {
        // sh() at top level is valid
        assert!(DescriptorTemplate::from_str("sh(wsh(sortedmulti(2,@0/**,@1/**)))").is_ok());
        assert!(DescriptorTemplate::from_str("sh(sortedmulti(2,@0/**,@1/**))").is_ok());

        // sh() inside wsh() is not allowed
        assert_eq!(
            DescriptorTemplate::from_str("wsh(sh(pk(@0/**)))"),
            Err(ParseError::InvalidScriptContext)
        );

        // sh() inside sh() is not allowed
        assert_eq!(
            DescriptorTemplate::from_str("sh(sh(pk(@0/**)))"),
            Err(ParseError::InvalidScriptContext)
        );

        // sh() inside tr() taptree is not allowed
        assert_eq!(
            DescriptorTemplate::from_str("tr(@0/**,sh(pk(@1/**)))"),
            Err(ParseError::InvalidScriptContext)
        );
    }

    #[test]
    fn test_wsh_only_allowed_top_level_or_inside_sh() {
        // wsh() at top level is valid
        assert!(DescriptorTemplate::from_str("wsh(sortedmulti(2,@0/**,@1/**))").is_ok());

        // wsh() inside sh() is valid
        assert!(DescriptorTemplate::from_str("sh(wsh(sortedmulti(2,@0/**,@1/**)))").is_ok());

        // wsh() inside wsh() is not allowed
        assert_eq!(
            DescriptorTemplate::from_str("wsh(wsh(pk(@0/**)))"),
            Err(ParseError::InvalidScriptContext)
        );

        // wsh() inside tr() taptree is not allowed
        assert_eq!(
            DescriptorTemplate::from_str("tr(@0/**,wsh(pk(@1/**)))"),
            Err(ParseError::InvalidScriptContext)
        );

        // wsh() inside sh(wsh()) is not allowed (double wrapping)
        assert_eq!(
            DescriptorTemplate::from_str("sh(wsh(wsh(pk(@0/**))))"),
            Err(ParseError::InvalidScriptContext)
        );
    }

    #[test]
    fn test_tr_only_allowed_top_level() {
        // tr() at top level is valid
        assert!(DescriptorTemplate::from_str("tr(@0/**)").is_ok());
        assert!(DescriptorTemplate::from_str("tr(@0/**,pk(@1/**))").is_ok());

        // tr() inside sh() is not allowed
        assert_eq!(
            DescriptorTemplate::from_str("sh(tr(@0/**))"),
            Err(ParseError::InvalidScriptContext)
        );

        // tr() inside wsh() is not allowed
        assert_eq!(
            DescriptorTemplate::from_str("wsh(tr(@0/**))"),
            Err(ParseError::InvalidScriptContext)
        );

        // tr() inside tr() taptree is not allowed
        assert_eq!(
            DescriptorTemplate::from_str("tr(@0/**,tr(@1/**))"),
            Err(ParseError::InvalidScriptContext)
        );
    }

    #[test]
    fn test_musig_not_allowed_in_wsh_inside_tr() {
        // musig() inside wsh() even within a tapscript should fail,
        // because wsh() is not allowed inside tr() in the first place
        assert_eq!(
            DescriptorTemplate::from_str("tr(@0/**,wsh(pk(musig(@1,@2)/**)))"),
            Err(ParseError::InvalidScriptContext)
        );
    }

    #[test]
    fn test_parser_rejects_zero_threshold() {
        assert_eq!(
            DescriptorTemplate::from_str("wsh(multi(0,@0/**,@1/**))"),
            Err(ParseError::InvalidMultisigQuorum)
        );
        assert_eq!(
            DescriptorTemplate::from_str("wsh(sortedmulti(0,@0/**,@1/**))"),
            Err(ParseError::InvalidMultisigQuorum)
        );
        assert_eq!(
            DescriptorTemplate::from_str("tr(@0/**,multi_a(0,@1/**,@2/**))"),
            Err(ParseError::InvalidMultisigQuorum)
        );
        assert_eq!(
            DescriptorTemplate::from_str("tr(@0/**,sortedmulti_a(0,@1/**,@2/**))"),
            Err(ParseError::InvalidMultisigQuorum)
        );
        assert_eq!(
            DescriptorTemplate::from_str("wsh(thresh(0,pk(@0/**)))"),
            Err(ParseError::InvalidMultisigQuorum)
        );
    }

    #[test]
    fn test_parser_rejects_threshold_exceeds_keys() {
        assert_eq!(
            DescriptorTemplate::from_str("wsh(multi(3,@0/**,@1/**))"),
            Err(ParseError::InvalidMultisigQuorum)
        );
        assert_eq!(
            DescriptorTemplate::from_str("wsh(sortedmulti(3,@0/**,@1/**))"),
            Err(ParseError::InvalidMultisigQuorum)
        );
        assert_eq!(
            DescriptorTemplate::from_str("tr(@0/**,multi_a(3,@1/**,@2/**))"),
            Err(ParseError::InvalidMultisigQuorum)
        );
        assert_eq!(
            DescriptorTemplate::from_str("tr(@0/**,sortedmulti_a(3,@1/**,@2/**))"),
            Err(ParseError::InvalidMultisigQuorum)
        );
    }

    #[test]
    fn test_parser_rejects_duplicate_musig_keys() {
        assert_eq!(
            DescriptorTemplate::from_str("tr(musig(@0,@0)/**)"),
            Err(ParseError::InvalidKey)
        );
        assert_eq!(
            DescriptorTemplate::from_str("tr(@0/**,pk(musig(@1,@1)/**))"),
            Err(ParseError::InvalidKey)
        );
        assert_eq!(
            DescriptorTemplate::from_str("tr(musig(@0,@1,@0)/**)"),
            Err(ParseError::InvalidKey)
        );
    }

    #[test]
    fn test_parser_rejects_too_many_keys_multi() {
        // multi/sortedmulti cap at 20 keys
        let mut s = String::from("wsh(multi(2");
        for i in 0..21 {
            s.push_str(&format!(",@{}/**", i));
        }
        s.push_str("))");
        assert_eq!(
            DescriptorTemplate::from_str(&s),
            Err(ParseError::TooManyKeys)
        );

        // Exactly 20 keys must still parse
        let mut s = String::from("wsh(multi(2");
        for i in 0..20 {
            s.push_str(&format!(",@{}/**", i));
        }
        s.push_str("))");
        assert!(DescriptorTemplate::from_str(&s).is_ok());
    }

    #[test]
    fn test_parser_accepts_more_than_20_keys_multi_a() {
        // multi_a allows >20 keys (Taproot OP_CHECKSIGADD pattern)
        let mut s = String::from("tr(@0/**,multi_a(2");
        for i in 1..=50 {
            s.push_str(&format!(",@{}/**", i));
        }
        s.push_str("))");
        assert!(DescriptorTemplate::from_str(&s).is_ok());
    }

    #[test]
    fn test_parser_rejects_deeply_nested_descriptors() {
        // Wrapper chains do NOT grow recursion depth — they are applied
        // iteratively inside `parse_descriptor`. A long chain should still
        // parse fine.
        let mut s = String::new();
        for _ in 0..1000 {
            s.push('j');
        }
        s.push_str(":0");
        assert!(DescriptorTemplate::from_str(&s).is_ok());

        // Andor nesting recurses through `parse_descriptor` — beyond the
        // depth limit, parsing must reject without overflowing the stack.
        let mut s = String::new();
        for _ in 0..(MAX_PARSE_DEPTH + 5) {
            s.push_str("andor(0,");
        }
        s.push('0');
        for _ in 0..(MAX_PARSE_DEPTH + 5) {
            s.push_str(",0)");
        }
        assert_eq!(
            DescriptorTemplate::from_str(&s),
            Err(ParseError::NestingTooDeep)
        );

        // Same for taproot tree braces.
        let mut s = String::from("tr(@0/**,");
        for _ in 0..(MAX_PARSE_DEPTH + 5) {
            s.push('{');
        }
        s.push_str("pk(@1/**)");
        for _ in 0..(MAX_PARSE_DEPTH + 5) {
            s.push_str(",pk(@2/**)}");
        }
        s.push(')');
        assert_eq!(
            DescriptorTemplate::from_str(&s),
            Err(ParseError::NestingTooDeep)
        );

        // A taproot tree nested up to the limit must still succeed. Build a
        // left-leaning tree of depth `MAX_PARSE_DEPTH - 4` (a few slots are
        // consumed by `tr(` and the script wrapping at the bottom).
        let inner_depth = MAX_PARSE_DEPTH - 4;
        let mut s = String::from("tr(@0/**,");
        for _ in 0..inner_depth {
            s.push('{');
        }
        s.push_str("pk(@1/**)");
        for _ in 0..inner_depth {
            s.push_str(",pk(@2/**)}");
        }
        s.push(')');
        assert!(DescriptorTemplate::from_str(&s).is_ok());
    }

    #[test]
    fn test_deserialize_rejects_oversized_descriptor() {
        use bitcoin::consensus::Encodable;
        let mut buf = Vec::<u8>::new();
        // Encode a VarInt that exceeds the descriptor-length cap. The reader
        // must reject before allocating.
        VarInt((MAX_SERIALIZED_DESCRIPTORTEMPLATE_LEN as u64) + 1)
            .consensus_encode(&mut buf)
            .unwrap();
        let mut cursor = bitcoin::io::Cursor::new(buf);
        let err = WalletPolicy::deserialize(&mut cursor).expect_err("expected error");
        assert!(matches!(err, encode::Error::ParseFailed(_)));
    }

    #[test]
    fn test_deserialize_rejects_oversized_key_count() {
        use bitcoin::consensus::Encodable;
        let mut buf = Vec::<u8>::new();
        // Minimal valid descriptor: empty descriptor template.
        VarInt(0).consensus_encode(&mut buf).unwrap();
        // Key count way above the cap.
        VarInt((MAX_SERIALIZED_KEY_COUNT as u64) + 1)
            .consensus_encode(&mut buf)
            .unwrap();
        let mut cursor = bitcoin::io::Cursor::new(buf);
        let err = WalletPolicy::deserialize(&mut cursor).expect_err("expected error");
        assert!(matches!(err, encode::Error::ParseFailed(_)));
    }

    #[test]
    fn test_to_descriptor_exact_output() {
        let xpub_str = "tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P";
        let keys = vec![
            KeyInformation::try_from(xpub_str).unwrap(),
            KeyInformation::try_from(xpub_str).unwrap(),
        ];
        let dt = DescriptorTemplate::from_str("wsh(sortedmulti(2,@0/**,@1/**))").unwrap();
        let out = dt.to_descriptor(&keys, false, 7).unwrap();
        let expected = format!("wsh(sortedmulti(2,{}/0/7,{}/0/7))", xpub_str, xpub_str);
        assert_eq!(out, expected);

        let dt = DescriptorTemplate::from_str("wsh(thresh(1,pk(@0/**),s:pk(@1/**)))").unwrap();
        let out = dt.to_descriptor(&keys, true, 3).unwrap();
        let expected = format!("wsh(thresh(1,pk({}/1/3),s:pk({}/1/3)))", xpub_str, xpub_str);
        assert_eq!(out, expected);
    }

    // ----- BIP-388 compliance: parser-level rules -----

    #[test]
    fn test_multipath_indices_must_be_distinct() {
        // A1: `/<NUM;NUM>/*` requires two distinct numbers.
        assert_eq!(
            parse_key_expression("@0/<5;5>/*", ParseContext::TopLevel),
            Err(ParseError::NonDistinctMultipath)
        );
        assert_eq!(
            DescriptorTemplate::from_str("tr(musig(@0,@1)/<3;3>/*)"),
            Err(ParseError::NonDistinctMultipath)
        );
        // Distinct indices (and the `/**` shorthand) still parse.
        assert!(parse_key_expression("@0/<0;1>/*", ParseContext::TopLevel).is_ok());
        assert!(parse_key_expression("@0/**", ParseContext::TopLevel).is_ok());
        assert!(parse_key_expression("@0/<9;3>/*", ParseContext::TopLevel).is_ok());
    }

    #[test]
    fn test_multi_only_inside_sh_or_wsh() {
        // A2: multi/sortedmulti are allowed only inside sh() or wsh().
        for allowed in [
            "sh(multi(2,@0/**,@1/**))",
            "wsh(multi(2,@0/**,@1/**))",
            "sh(wsh(multi(2,@0/**,@1/**)))",
            "sh(sortedmulti(2,@0/**,@1/**))",
            "wsh(sortedmulti(2,@0/**,@1/**))",
        ] {
            assert!(
                DescriptorTemplate::from_str(allowed).is_ok(),
                "should parse: {allowed}"
            );
        }
        for rejected in [
            "multi(2,@0/**,@1/**)",
            "sortedmulti(2,@0/**,@1/**)",
            "tr(@0/**,multi(2,@1/**,@2/**))",
            "tr(@0/**,sortedmulti(2,@1/**,@2/**))",
        ] {
            assert_eq!(
                DescriptorTemplate::from_str(rejected),
                Err(ParseError::InvalidScriptContext),
                "should be rejected: {rejected}"
            );
        }
    }

    #[test]
    fn test_multi_a_only_inside_tr() {
        // A3: multi_a/sortedmulti_a are tapscript-only, so allowed only in tr().
        assert!(DescriptorTemplate::from_str("tr(@0/**,multi_a(2,@1/**,@2/**))").is_ok());
        assert!(DescriptorTemplate::from_str("tr(@0/**,sortedmulti_a(2,@1/**,@2/**))").is_ok());
        for rejected in [
            "multi_a(2,@0/**,@1/**)",
            "sortedmulti_a(2,@0/**,@1/**)",
            "wsh(multi_a(2,@0/**,@1/**))",
            "sh(wsh(multi_a(2,@0/**,@1/**)))",
        ] {
            assert_eq!(
                DescriptorTemplate::from_str(rejected),
                Err(ParseError::InvalidScriptContext),
                "should be rejected: {rejected}"
            );
        }
    }

    #[test]
    fn test_pkh_allowed_in_miniscript() {
        // Per the chosen interpretation, `pkh` is valid miniscript both inside
        // wsh and inside a taproot tree (the `c:pk_h` form).
        assert!(DescriptorTemplate::from_str("wsh(pkh(@0/**))").is_ok());
        assert!(DescriptorTemplate::from_str("tr(@0/**,pkh(@1/**))").is_ok());
        assert!(DescriptorTemplate::from_str("wsh(or_d(pk(@0/**),pkh(@1/**)))").is_ok());
    }

    // ----- BIP-388 compliance: whole-policy validation in WalletPolicy::new -----

    #[test]
    fn test_policy_requires_key_placeholder() {
        // B1: a policy with no key placeholder is rejected.
        assert_eq!(
            WalletPolicy::new("older(12345)", vec![]),
            Err(ParseError::NoKeyPlaceholders)
        );
    }

    #[test]
    fn test_policy_key_index_and_count() {
        // B2: an out-of-range index is rejected.
        assert_eq!(
            WalletPolicy::new("wsh(multi(2,@0/**,@2/**))", distinct_keys(2)),
            Err(ParseError::InvalidKeyIndex)
        );
        // An unused key (count mismatch) is rejected.
        assert_eq!(
            WalletPolicy::new("pkh(@0/**)", distinct_keys(2)),
            Err(ParseError::KeyIndexCountMismatch)
        );
        // Too few keys for the referenced placeholders is rejected.
        assert_eq!(
            WalletPolicy::new("wsh(sortedmulti(2,@0/**,@1/**))", distinct_keys(1)),
            Err(ParseError::InvalidKeyIndex)
        );
        // Exactly the right keys, all used: OK.
        assert!(WalletPolicy::new("wsh(sortedmulti(2,@0/**,@1/**))", distinct_keys(2)).is_ok());
    }

    #[test]
    fn test_policy_placeholder_order_is_tolerated() {
        // B5: the `@i` first-appearance ordering is a SHOULD in BIP-388, so an
        // out-of-order template with a full, correct key set is accepted.
        assert!(WalletPolicy::new("wsh(sortedmulti(2,@1/**,@0/**))", distinct_keys(2)).is_ok());
    }

    #[test]
    fn test_policy_rejects_duplicate_keys() {
        // B3: the public keys must be pairwise distinct.
        assert_eq!(
            WalletPolicy::new(
                "wsh(sortedmulti(2,@0/**,@1/**))",
                vec![koi(XPUB_A), koi(XPUB_A)]
            ),
            Err(ParseError::DuplicateKey)
        );
    }

    #[test]
    fn test_policy_multipath_must_be_disjoint() {
        // B4: repeated use of the same placeholder must use disjoint multipaths.
        // `/**` = `/<0;1>/*`, so both occurrences share {0,1}.
        assert_eq!(
            WalletPolicy::new("wsh(multi(2,@0/**,@0/**))", distinct_keys(1)),
            Err(ParseError::OverlappingMultipath)
        );
        // Partial overlap ({0,1} vs {1,2}) is also rejected.
        assert_eq!(
            WalletPolicy::new("wsh(multi(2,@0/<0;1>/*,@0/<1;2>/*))", distinct_keys(1)),
            Err(ParseError::OverlappingMultipath)
        );
        // Disjoint multipaths for the same placeholder are allowed.
        assert!(WalletPolicy::new("wsh(multi(2,@0/<0;1>/*,@0/<2;3>/*))", distinct_keys(1)).is_ok());
    }

    #[test]
    fn test_policy_musig_identity_is_by_index_set() {
        // Two musig placeholders are "the same key" iff they have the same set
        // of indices, regardless of order. Same set + same multipath overlaps.
        assert_eq!(
            WalletPolicy::new(
                "tr(musig(@0,@1)/<0;1>/*,pk(musig(@1,@0)/<0;1>/*))",
                distinct_keys(2)
            ),
            Err(ParseError::OverlappingMultipath)
        );
        // Same set but disjoint multipaths is fine.
        assert!(WalletPolicy::new(
            "tr(musig(@0,@1)/<0;1>/*,pk(musig(@1,@0)/<2;3>/*))",
            distinct_keys(2)
        )
        .is_ok());
    }

    #[test]
    fn test_standard_bip388_policies_are_valid() {
        // The canonical BIP-388 single-account templates, end to end through
        // WalletPolicy::new (template + key vector), each with the right number
        // of distinct keys.
        let cases: &[(&str, usize)] = &[
            ("pkh(@0/**)", 1),                      // BIP-44
            ("sh(wpkh(@0/**))", 1),                 // BIP-49
            ("wpkh(@0/**)", 1),                     // BIP-84
            ("tr(@0/**)", 1),                       // BIP-86
            ("wsh(sortedmulti(2,@0/**,@1/**))", 2), // BIP-48 P2WSH multisig
            ("sh(wsh(sortedmulti(2,@0/**,@1/**)))", 2),
        ];
        for &(template, n) in cases {
            assert!(
                WalletPolicy::new(template, distinct_keys(n)).is_ok(),
                "should be a valid policy: {template}"
            );
        }
    }

    #[test]
    fn test_wallet_policy_serialize_roundtrip() {
        // Round-trip a real policy (with origin info) through serialize/deserialize.
        let policy = WalletPolicy::new(
            "wsh(sortedmulti(2,@0/**,@1/**))",
            vec![
                koi("[76223a6e/48'/1'/0'/1']tpubDE7NQymr4AFtcJXi9TaWZtrhAdy8QyKmT4U6b9qYByAxCzoyMJ8zw5d8xVLVpbTRAEqP8pVUxjLE2vDt1rSFjaiS8DSz1QcNZ8D1qxUMx1g"),
                koi("[f5acc2fd/48'/1'/0'/1']tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY"),
            ],
        )
        .unwrap();

        let bytes = policy.serialize();
        let mut cursor = bitcoin::io::Cursor::new(bytes);
        let decoded = WalletPolicy::deserialize(&mut cursor).expect("round-trip should succeed");
        assert_eq!(policy, decoded);
    }
}
