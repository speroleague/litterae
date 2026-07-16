//! Turns the compose editor's raw HTML into what actually gets sent:
//! sanitized markup for the `text/html` part, plus a derived
//! `text/plain` fallback. The account's own content, but never trusted
//! as already-safe -- anyone can call `/jmap/api` directly with
//! hand-crafted `bodyHtml`, bypassing the frontend editor entirely.
//!
//! Deliberately a separate module from `html_sanitize.rs` (the inbound
//! sanitizer for attacker-controlled mail), not shared code, because the
//! threat models differ: inbound needs tracker-blocking and link-
//! neutering for content from strangers; outbound needs email-client
//! compatibility and defense in depth for the account's own composed
//! content, with a much smaller allowlist (no images/links beyond what
//! the editor itself can produce).

use html5ever::interface::Attribute;
use html5ever::tendril::TendrilSink;
use html5ever::{local_name, ns, ParseOpts, QualName};
use markup5ever_rcdom::{Handle, NodeData, RcDom};

/// The fixed palette a `<span style="color: ...">` may use, as RGB
/// triples rather than exact strings. A browser's `CSSStyleDeclaration`
/// always normalizes a color it's asked to serialize to `rgb(r, g, b)`
/// form regardless of what notation was originally set (confirmed: the
/// compose editor's Color extension sets a hex value, but
/// `editor.getHTML()` comes back with `color: rgb(...)`) -- so this
/// can't be a fixed set of literal strings the way the rest of this
/// module's allowlists are; it has to parse and compare numerically.
pub(crate) const ALLOWED_COLORS: &[(u8, u8, u8)] = &[
    (0x1a, 0x1a, 0x1a),
    (0xd9, 0x26, 0x26),
    (0xd9, 0x77, 0x06),
    (0x16, 0xa3, 0x4a),
    (0x25, 0x63, 0xeb),
    (0x7c, 0x3a, 0xed),
];

/// Whether a `style` attribute value is *exactly* `color: #rrggbb` or
/// `color: rgb(r, g, b)` for one of `ALLOWED_COLORS` -- nothing else,
/// no trailing declarations. ammonia's own built-in
/// `filter_style_properties` only allowlists CSS property *names* and
/// re-serializes values verbatim (its own test shows `url(...)`
/// surviving inside an allowed property), so a property-name allowlist
/// is not adequate here; parsing down to a concrete (r,g,b) and checking
/// set membership is what actually forecloses CSS-based exfiltration
/// (`background: url(...)`) and any other injection through this
/// attribute, regardless of which notation it arrives in.
pub(crate) fn is_allowed_color_style(value: &str) -> bool {
    parse_color_style(value).is_some_and(|rgb| ALLOWED_COLORS.contains(&rgb))
}

fn parse_color_style(value: &str) -> Option<(u8, u8, u8)> {
    // The compose editor's own serialization includes a trailing `;`
    // (confirmed empirically: `editor.getHTML()` produces
    // `color: rgb(r, g, b);`, not `color: rgb(r, g, b)`) -- strip at
    // most one, so this still requires the value to be a single
    // declaration and nothing else (`rejects_malformed_color_values_
    // that_still_end_in_a_paren` covers a trailing-declaration
    // injection attempt that doesn't end in `;`).
    let value = value.trim();
    let value = value.strip_suffix(';').unwrap_or(value).trim();
    let rest = value.strip_prefix("color:")?.trim();
    if let Some(hex) = rest.strip_prefix('#') {
        if hex.len() != 6 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
        let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
        let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
        return Some((r, g, b));
    }
    let inner = rest.strip_prefix("rgb(")?.strip_suffix(')')?;
    let mut parts = inner.split(',').map(str::trim);
    let r: u8 = parts.next()?.parse().ok()?;
    let g: u8 = parts.next()?.parse().ok()?;
    let b: u8 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((r, g, b))
}

/// Sanitizes compose-editor HTML down to a small, explicit allowlist
/// before it's signed/queued/stored. `img[src]` only ever survives as
/// `cid:u{id}` (an upload this account already scanned and sealed via
/// `/jmap/upload`) -- `data:` is deliberately *not* an allowed scheme
/// here, unlike the inbound sanitizer, so there's no way to smuggle an
/// unscanned image straight into a composed message.
pub fn sanitize_outbound(raw_html: &str) -> String {
    let tags = [
        "p",
        "br",
        "strong",
        "b",
        "em",
        "i",
        "u",
        "ul",
        "ol",
        "li",
        "blockquote",
        "pre",
        "code",
        "h1",
        "h2",
        "h3",
        "a",
        "span",
        "img",
    ]
    .into_iter()
    .collect();

    let tag_attributes = [
        ("a", ["href"].into_iter().collect()),
        ("span", ["style"].into_iter().collect()),
        ("img", ["src"].into_iter().collect()),
    ]
    .into_iter()
    .collect();

    ammonia::Builder::default()
        .tags(tags)
        .clean_content_tags(["script", "style"].into_iter().collect())
        .tag_attributes(tag_attributes)
        .generic_attributes(Default::default())
        .url_schemes(["http", "https", "mailto", "cid"].into_iter().collect())
        .attribute_filter(|element, attribute, value| match (element, attribute) {
            ("span", "style") => is_allowed_color_style(value).then(|| value.to_string().into()),
            // `url_schemes` is a single global allowlist shared by every
            // url-bearing attribute (ammonia doesn't scope it per tag),
            // so `http`/`https` being allowed for `a[href]` would also
            // let them through here -- an image must only ever be a
            // `cid:` reference to something this account already
            // uploaded and scanned, never a remote URL or a `data:` URI
            // smuggled straight past the upload/ClamAV step.
            ("img", "src") => value.starts_with("cid:").then(|| value.to_string().into()),
            _ => Some(value.to_string().into()),
        })
        .clean(raw_html)
        .to_string()
}

/// Pulls `u{digits}` upload references out of already-sanitized HTML's
/// `img[src="cid:..."]` attributes. Anything else after `cid:` is left
/// alone as a harmless dangling reference -- the editor never produces
/// any other form, so there's nothing else to resolve.
pub fn extract_inline_cids(sanitized_html: &str) -> Vec<String> {
    let dom = parse_fragment(sanitized_html);
    let root = first_child(&dom.document).unwrap_or_else(|| dom.document.clone());
    let mut cids = Vec::new();
    collect_cids(&root, &mut cids);
    cids
}

fn collect_cids(handle: &Handle, cids: &mut Vec<String>) {
    if let NodeData::Element { ref name, ref attrs, .. } = handle.data {
        if name.local.as_ref() == "img" {
            if let Some(src) = attr_value(&attrs.borrow(), "src") {
                if let Some(cid) = src.strip_prefix("cid:") {
                    if is_upload_blob_id(cid) {
                        cids.push(cid.to_string());
                    }
                }
            }
        }
    }
    for child in handle.children.borrow().iter() {
        collect_cids(child, cids);
    }
}

fn is_upload_blob_id(value: &str) -> bool {
    value
        .strip_prefix('u')
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
}

/// Derives a readable `text/plain` fallback from already-sanitized HTML
/// -- the thing that guarantees the text part actually reflects what
/// was sent, rather than a second hand-maintained copy the two could
/// drift out of sync with.
pub fn html_to_text(sanitized_html: &str) -> String {
    let dom = parse_fragment(sanitized_html);
    let root = first_child(&dom.document).unwrap_or_else(|| dom.document.clone());
    let mut out = String::new();
    let mut list_stack: Vec<ListKind> = Vec::new();
    walk_text(&root, &mut out, &mut list_stack);
    normalize_whitespace(&out)
}

enum ListKind {
    Bullet,
    Ordered(u32),
}

fn walk_text(handle: &Handle, out: &mut String, list_stack: &mut Vec<ListKind>) {
    match &handle.data {
        NodeData::Text { contents } => out.push_str(&contents.borrow()),
        NodeData::Element { ref name, ref attrs, .. } => {
            let tag = name.local.as_ref();
            match tag {
                "br" => out.push('\n'),
                "p" | "h1" | "h2" | "h3" | "blockquote" | "pre" => {
                    push_block_break(out);
                    walk_children(handle, out, list_stack);
                    out.push('\n');
                }
                "ul" => {
                    list_stack.push(ListKind::Bullet);
                    walk_children(handle, out, list_stack);
                    list_stack.pop();
                }
                "ol" => {
                    list_stack.push(ListKind::Ordered(1));
                    walk_children(handle, out, list_stack);
                    list_stack.pop();
                }
                "li" => {
                    if !out.is_empty() && !out.ends_with('\n') {
                        out.push('\n');
                    }
                    match list_stack.last_mut() {
                        Some(ListKind::Bullet) => out.push_str("- "),
                        Some(ListKind::Ordered(n)) => {
                            out.push_str(&format!("{n}. "));
                            *n += 1;
                        }
                        None => out.push_str("- "),
                    }
                    walk_children(handle, out, list_stack);
                    out.push('\n');
                }
                "a" => {
                    let href = attr_value(&attrs.borrow(), "href");
                    let start = out.len();
                    walk_children(handle, out, list_stack);
                    if let Some(href) = href {
                        if out[start..] != href {
                            out.push_str(&format!(" ({href})"));
                        }
                    }
                }
                _ => walk_children(handle, out, list_stack),
            }
        }
        _ => {}
    }
}

fn walk_children(handle: &Handle, out: &mut String, list_stack: &mut Vec<ListKind>) {
    for child in handle.children.borrow().iter() {
        walk_text(child, out, list_stack);
    }
}

/// Ensures the next block starts on its own blank line, without piling
/// up extra blank lines if one is already there.
fn push_block_break(out: &mut String) {
    if out.is_empty() {
        return;
    }
    if out.ends_with("\n\n") {
        return;
    }
    if out.ends_with('\n') {
        out.push('\n');
    } else {
        out.push_str("\n\n");
    }
}

/// Collapses 3+ blank lines down to one, trims the ends.
fn normalize_whitespace(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut blank_run = 0;
    for line in text.lines() {
        if line.trim().is_empty() {
            blank_run += 1;
            if blank_run > 1 {
                continue;
            }
        } else {
            blank_run = 0;
        }
        result.push_str(line);
        result.push('\n');
    }
    result.trim().to_string()
}

fn parse_fragment(html: &str) -> RcDom {
    let context = QualName::new(None, ns!(html), local_name!("div"));
    html5ever::driver::parse_fragment(RcDom::default(), ParseOpts::default(), context, vec![], false)
        .one(html)
}

fn first_child(handle: &Handle) -> Option<Handle> {
    handle.children.borrow().first().cloned()
}

fn attr_value(attrs: &[Attribute], name: &str) -> Option<String> {
    attrs
        .iter()
        .find(|a| a.name.local.as_ref() == name)
        .map(|a| a.value.to_string())
}

#[cfg(test)]
mod tests {
    use html5ever::serialize::{serialize, SerializeOpts, TraversalScope};
    use markup5ever_rcdom::SerializableHandle;

    use super::*;

    fn serialize_dom(dom: &RcDom) -> String {
        let root = first_child(&dom.document).unwrap_or_else(|| dom.document.clone());
        let handle: SerializableHandle = root.into();
        let mut buf = Vec::new();
        serialize(
            &mut buf,
            &handle,
            SerializeOpts {
                traversal_scope: TraversalScope::ChildrenOnly(None),
                ..Default::default()
            },
        )
        .unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn allows_basic_formatting_and_lists() {
        let out = sanitize_outbound("<p>Hello <b>world</b></p><ul><li>one</li></ul>");
        assert!(out.contains("<b>world</b>"));
        assert!(out.contains("<ul><li>one</li></ul>"));
    }

    #[test]
    fn allows_headings_blockquote_and_code() {
        let out = sanitize_outbound("<h1>Title</h1><blockquote>quoted</blockquote><pre><code>fn x() {}</code></pre>");
        assert!(out.contains("<h1>Title</h1>"));
        assert!(out.contains("<blockquote>quoted</blockquote>"));
        assert!(out.contains("<pre><code>fn x() {}</code></pre>"));
    }

    #[test]
    fn allows_http_and_mailto_links_only() {
        let out = sanitize_outbound(
            r#"<a href="https://example.com">web</a><a href="mailto:a@example.com">mail</a><a href="javascript:alert(1)">bad</a>"#,
        );
        assert!(out.contains(r#"href="https://example.com""#));
        assert!(out.contains(r#"href="mailto:a@example.com""#));
        assert!(!out.contains("javascript"));
    }

    #[test]
    fn allows_cid_image_but_not_data_or_http() {
        let out = sanitize_outbound(
            r#"<img src="cid:u42"><img src="data:image/gif;base64,AA=="><img src="https://evil.example/pixel.gif">"#,
        );
        assert!(out.contains(r#"src="cid:u42""#));
        assert!(!out.contains("data:"));
        assert!(!out.contains("evil.example"));
    }

    #[test]
    fn allows_exact_palette_color_and_drops_others() {
        let out = sanitize_outbound(
            r#"<span style="color: #d92626">red</span><span style="color: #123456">bad</span><span style="background: url(https://evil.example/x)">exfil</span>"#,
        );
        assert!(out.contains(r#"style="color: #d92626""#));
        assert!(!out.contains("#123456"));
        assert!(!out.contains("url("));
        assert!(!out.contains("evil.example"));
    }

    #[test]
    fn allows_rgb_form_of_an_allowed_color() {
        // A browser's `CSSStyleDeclaration` always normalizes a color it
        // serializes to `rgb(r, g, b)` regardless of what notation was
        // set -- confirmed empirically: the compose editor's Color
        // extension sets a hex value, but `editor.getHTML()` comes back
        // with `rgb(...);` (semicolon included). This exact value --
        // including the trailing `;` -- is what a real end-to-end
        // browser test produced; an earlier version of this test used
        // the same value *without* the semicolon and passed while the
        // real editor output was silently rejected, so the semicolon is
        // deliberately included here as the authoritative regression
        // case, not simplified away again.
        let out = sanitize_outbound(r#"<span style="color: rgb(217, 38, 38);">red</span>"#);
        assert!(out.contains("color: rgb(217, 38, 38)"));
    }

    #[test]
    fn rejects_rgb_value_outside_the_palette() {
        let out = sanitize_outbound(r#"<span style="color: rgb(1, 2, 3)">bad</span>"#);
        assert!(!out.contains("style="));
    }

    #[test]
    fn rejects_malformed_color_values_that_still_end_in_a_paren() {
        // strip_suffix(')') alone would be fooled by this; the numeric
        // parse of each component is what actually rejects it.
        let out = sanitize_outbound(
            r#"<span style="color: rgb(217, 38, 38); background:url(evil)">x</span>"#,
        );
        assert!(!out.contains("style="));
        assert!(!out.contains("evil"));
    }

    #[test]
    fn strips_script_tag_and_its_content() {
        let out = sanitize_outbound("<p>hi</p><script>alert(1)</script>");
        assert!(!out.contains("script"));
        assert!(!out.contains("alert"));
    }

    #[test]
    fn strips_event_handler_attributes() {
        let out = sanitize_outbound(r#"<p onclick="alert(1)">hi</p>"#);
        assert!(!out.contains("onclick"));
        assert!(!out.contains("alert"));
    }

    #[test]
    fn strips_generic_lang_and_title_attributes() {
        let out = sanitize_outbound(r#"<p lang="en" title="x">hi</p>"#);
        assert!(!out.contains("lang="));
        assert!(!out.contains("title="));
    }

    #[test]
    fn strips_disallowed_tags_and_attributes() {
        let out = sanitize_outbound(r#"<div class="x"><svg></svg><iframe></iframe>text</div>"#);
        assert!(!out.contains("<div"));
        assert!(!out.contains("class="));
        assert!(!out.contains("svg"));
        assert!(!out.contains("iframe"));
        assert!(out.contains("text"));
    }

    #[test]
    fn extract_inline_cids_finds_upload_ids_only() {
        let html = sanitize_outbound(r#"<img src="cid:u7"><img src="cid:u12">"#);
        let mut cids = extract_inline_cids(&html);
        cids.sort();
        assert_eq!(cids, vec!["u12".to_string(), "u7".to_string()]);
    }

    #[test]
    fn extract_inline_cids_ignores_non_upload_shapes() {
        let dom = {
            let context = QualName::new(None, ns!(html), local_name!("div"));
            html5ever::driver::parse_fragment(RcDom::default(), ParseOpts::default(), context, vec![], false)
                .one(r#"<img src="cid:not-an-upload">"#)
        };
        let raw = serialize_dom(&dom);
        assert_eq!(extract_inline_cids(&raw), Vec::<String>::new());
    }

    #[test]
    fn html_to_text_renders_paragraphs_and_lists() {
        let text = html_to_text("<p>Hello there.</p><ul><li>one</li><li>two</li></ul>");
        assert!(text.contains("Hello there."));
        assert!(text.contains("- one"));
        assert!(text.contains("- two"));
    }

    #[test]
    fn html_to_text_numbers_ordered_lists() {
        let text = html_to_text("<ol><li>first</li><li>second</li></ol>");
        assert!(text.contains("1. first"));
        assert!(text.contains("2. second"));
    }

    #[test]
    fn html_to_text_includes_link_target() {
        let text = html_to_text(r#"<a href="https://example.com">click here</a>"#);
        assert!(text.contains("click here (https://example.com)"));
    }

    #[test]
    fn html_to_text_collapses_excess_blank_lines() {
        let text = html_to_text("<p>a</p><p></p><p></p><p>b</p>");
        assert!(!text.contains("\n\n\n"));
    }
}
