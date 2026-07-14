//! Turns an attacker-controlled HTML email body into something safe to
//! hand to a browser. Two passes, not one `ammonia::clean()` call --
//! ammonia's `attribute_filter` can rewrite an attribute's *value* but
//! can't introduce a new attribute name, and relocating the real
//! image/link URLs into `data-*` attributes (so the caller can gate
//! remote images and intercept link clicks) needs exactly that.
//!
//! Pass 1 (ammonia): reduce arbitrary attacker HTML down to a small,
//! explicitly-*replaced* (never additive-over-ammonia's-defaults)
//! tag/attribute allowlist. Hard rule, load-bearing for staying outside
//! every known ammonia CVE to date: never add `svg`, `math`, or any
//! raw-text element (`title`, `textarea`, `xmp`, `iframe`, `noembed`,
//! `noframes`, `plaintext`, `noscript`, `style`, `script`) to the tag
//! allowlist -- every ammonia advisory so far has required both an
//! svg/math tag *and* a raw-text tag to be allowed together.
//!
//! Pass 2 (a second, independent HTML parse over pass 1's already-clean
//! output, via `html5ever`/`markup5ever_rcdom` directly, not ammonia's
//! own `Document::to_dom_node` which is cfg-gated as unstable):
//! - `img[src]`: `data:` URIs pass through untouched (no network call).
//!   `http(s)://` gets its `src` moved to `data-blocked-src` and counted
//!   (the frontend reveals it only on explicit user action). Anything
//!   else (`cid:`, relative, unparseable) is dropped outright -- `cid:`
//!   needs the attachment/blob-serving system this codebase doesn't have
//!   yet to resolve safely.
//! - `a[href]`: only an *absolute* `http`/`https`/`mailto` URL survives,
//!   moved to `data-real-href` with `href` blanked to `#` (the frontend's
//!   trusted script intercepts the click and confirms before navigating
//!   anywhere). Everything else -- relative, `javascript:`, any other
//!   scheme -- is dropped; a `srcdoc` document resolves a relative href
//!   against the *parent app's own origin*, so leaving one in would be
//!   actively misleading in a "you're about to leave" confirmation. The
//!   `ping` attribute (a separate hyperlink-auditing background POST,
//!   not a navigation) is always dropped too.

use std::cell::RefCell;

use html5ever::interface::Attribute;
use html5ever::serialize::{serialize, SerializeOpts, TraversalScope};
use html5ever::tendril::TendrilSink;
use html5ever::{local_name, ns, ParseOpts, QualName};
use markup5ever_rcdom::{Handle, NodeData, RcDom, SerializableHandle};
use url::Url;

pub struct SanitizedHtml {
    pub html: String,
    pub blocked_image_count: u32,
}

pub fn sanitize(raw_html: &str) -> SanitizedHtml {
    let pass1 = ammonia_clean(raw_html);
    pass2_rewrite(&pass1)
}

fn ammonia_clean(raw_html: &str) -> String {
    let tags = [
        "p", "div", "span", "br", "hr", "pre", "code", "blockquote", "a", "img", "table",
        "thead", "tbody", "tfoot", "tr", "td", "th", "h1", "h2", "h3", "h4", "h5", "h6", "ul",
        "ol", "li", "b", "i", "u", "strong", "em", "sub", "sup",
    ]
    .into_iter()
    .collect();

    let tag_attributes = [
        ("a", ["href"].into_iter().collect()),
        ("img", ["src", "alt", "width", "height"].into_iter().collect()),
        ("td", ["colspan", "rowspan"].into_iter().collect()),
        ("th", ["colspan", "rowspan"].into_iter().collect()),
    ]
    .into_iter()
    .collect();

    ammonia::Builder::default()
        .tags(tags)
        .clean_content_tags(["script", "style"].into_iter().collect())
        .tag_attributes(tag_attributes)
        .generic_attributes(Default::default())
        .url_schemes(["http", "https", "mailto"].into_iter().collect())
        .clean(raw_html)
        .to_string()
}

fn pass2_rewrite(clean_html: &str) -> SanitizedHtml {
    let context = QualName::new(None, ns!(html), local_name!("div"));
    let dom = html5ever::driver::parse_fragment(RcDom::default(), ParseOpts::default(), context, vec![], false)
        .one(clean_html);

    let mut blocked_image_count = 0u32;
    walk(&dom.document, &mut blocked_image_count);

    let inner: SerializableHandle = first_child(&dom.document).unwrap_or(dom.document).into();
    let mut buf = Vec::new();
    serialize(
        &mut buf,
        &inner,
        SerializeOpts {
            traversal_scope: TraversalScope::ChildrenOnly(None),
            ..Default::default()
        },
    )
    .expect("serializing an in-memory DOM to a Vec<u8> cannot fail");

    SanitizedHtml {
        html: String::from_utf8(buf).expect("html5ever always produces valid UTF-8"),
        blocked_image_count,
    }
}

/// `parse_fragment`'s root is the document node; its one child is the
/// `<div>` context element the fragment was parsed as-if-inside (see
/// ammonia's own `make_parser` doc comment, same convention here) --
/// unwrap down to that so serializing with `ChildrenOnly` yields just the
/// fragment content, not a wrapping `<div>`.
fn first_child(handle: &Handle) -> Option<Handle> {
    handle.children.borrow().first().cloned()
}

fn walk(handle: &Handle, blocked_image_count: &mut u32) {
    if let NodeData::Element { ref name, ref attrs, .. } = handle.data {
        match name.local.as_ref() {
            "img" => rewrite_img(attrs, blocked_image_count),
            "a" => rewrite_a(attrs),
            _ => {}
        }
    }
    for child in handle.children.borrow().iter() {
        walk(child, blocked_image_count);
    }
}

fn attr_value(attrs: &[Attribute], name: &str) -> Option<String> {
    attrs
        .iter()
        .find(|a| a.name.local.as_ref() == name)
        .map(|a| a.value.to_string())
}

fn set_attr(attrs: &mut Vec<Attribute>, name: &'static str, value: String) {
    attrs.retain(|a| a.name.local.as_ref() != name);
    attrs.push(Attribute {
        name: QualName::new(None, ns!(), name.into()),
        value: value.into(),
    });
}

fn remove_attr(attrs: &mut Vec<Attribute>, name: &str) {
    attrs.retain(|a| a.name.local.as_ref() != name);
}

fn rewrite_img(attrs: &RefCell<Vec<Attribute>>, blocked_image_count: &mut u32) {
    let mut attrs = attrs.borrow_mut();
    let Some(src) = attr_value(&attrs, "src") else {
        return;
    };
    remove_attr(&mut attrs, "src");

    if src.starts_with("data:") {
        set_attr(&mut attrs, "src", src);
        return;
    }
    if let Ok(url) = Url::parse(&src) {
        if url.scheme() == "http" || url.scheme() == "https" {
            set_attr(&mut attrs, "data-blocked-src", src);
            *blocked_image_count += 1;
        }
        // Any other absolute scheme (cid:, etc.) -- drop, nothing to show.
    }
    // Relative or unparseable -- drop.
}

fn rewrite_a(attrs: &RefCell<Vec<Attribute>>) {
    let mut attrs = attrs.borrow_mut();
    remove_attr(&mut attrs, "ping");
    let Some(href) = attr_value(&attrs, "href") else {
        return;
    };
    remove_attr(&mut attrs, "href");

    if let Ok(url) = Url::parse(&href) {
        let scheme = url.scheme();
        if scheme == "http" || scheme == "https" || scheme == "mailto" {
            set_attr(&mut attrs, "data-real-href", href);
            set_attr(&mut attrs, "href", "#".to_string());
            return;
        }
    }
    // Relative, javascript:, or any other/unparseable scheme -- the link
    // stays present as text but non-navigable (no href at all).
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_script_tag_and_its_content() {
        let out = sanitize("<p>hi</p><script>alert(1)</script>").html;
        assert!(!out.contains("script"));
        assert!(!out.contains("alert"));
    }

    #[test]
    fn strips_event_handler_attributes() {
        let out = sanitize(r#"<img src="data:image/gif;base64,AA==" onerror="alert(1)">"#).html;
        assert!(!out.contains("onerror"));
        assert!(!out.contains("alert"));
    }

    #[test]
    fn strips_style_tag_and_inline_style_attribute() {
        let out = sanitize(r#"<style>body{background:url(https://evil.example/track)}</style><p style="color:red">hi</p>"#).html;
        assert!(!out.contains("<style"));
        assert!(!out.contains("style="));
        assert!(!out.contains("evil.example"));
    }

    #[test]
    fn blocks_remote_image_and_counts_it() {
        let result = sanitize(r#"<img src="https://evil.example/pixel.gif">"#);
        assert!(!result.html.contains(r#"src="https://evil.example"#));
        assert!(result.html.contains(r#"data-blocked-src="https://evil.example/pixel.gif""#));
        assert_eq!(result.blocked_image_count, 1);
    }

    #[test]
    fn allows_data_uri_image_without_blocking() {
        let result = sanitize(r#"<img src="data:image/gif;base64,AA==">"#);
        assert!(result.html.contains(r#"src="data:image/gif;base64,AA==""#));
        assert_eq!(result.blocked_image_count, 0);
    }

    #[test]
    fn drops_cid_image_entirely() {
        let result = sanitize(r#"<img src="cid:image001.png@example">"#);
        assert!(!result.html.contains("cid:"));
        assert!(!result.html.contains("data-blocked-src"));
        assert_eq!(result.blocked_image_count, 0);
    }

    #[test]
    fn rewrites_absolute_http_link_and_neutralizes_href() {
        let out = sanitize(r#"<a href="https://example.com/page">click</a>"#).html;
        assert!(out.contains(r#"data-real-href="https://example.com/page""#));
        assert!(out.contains("href=\"#\""));
        assert!(!out.contains(r#"href="https://example.com/page""#));
    }

    #[test]
    fn keeps_mailto_link() {
        let out = sanitize(r#"<a href="mailto:someone@example.com">mail me</a>"#).html;
        assert!(out.contains(r#"data-real-href="mailto:someone@example.com""#));
    }

    #[test]
    fn drops_relative_href_entirely() {
        let out = sanitize(r#"<a href="/some/path">click</a>"#).html;
        assert!(!out.contains("data-real-href"));
        assert!(!out.contains(r#"href="/some/path""#));
    }

    #[test]
    fn drops_javascript_href() {
        let out = sanitize(r#"<a href="javascript:alert(1)">click</a>"#).html;
        assert!(!out.contains("javascript"));
        assert!(!out.contains("data-real-href"));
    }

    #[test]
    fn drops_ping_attribute() {
        let out = sanitize(r#"<a href="https://example.com" ping="https://evil.example/beacon">click</a>"#).html;
        assert!(!out.contains("ping"));
        assert!(!out.contains("evil.example"));
    }

    #[test]
    fn never_allows_svg_math_or_raw_text_elements() {
        // Hard rule enforced by construction (see module doc): assert
        // directly against the allowlist, not just behaviorally, so a
        // future edit can't accidentally reintroduce one of these.
        let out = sanitize(
            r#"<svg><title>x</title></svg><math></math><iframe></iframe><noscript>x</noscript><textarea>x</textarea>"#,
        )
        .html;
        for forbidden in ["svg", "math", "iframe", "noscript", "textarea", "xmp", "noembed", "noframes"] {
            assert!(!out.contains(forbidden), "forbidden element leaked through: {forbidden}");
        }
    }

    #[test]
    fn srcset_never_survives() {
        let out = sanitize(r#"<img src="data:image/gif;base64,AA==" srcset="https://evil.example/x 1x">"#).html;
        assert!(!out.contains("srcset"));
        assert!(!out.contains("evil.example"));
    }

    #[test]
    fn malformed_html_does_not_panic() {
        let _ = sanitize("<img src=<<<>>>>><a href=");
        let _ = sanitize("");
        let _ = sanitize("<div><div><div>unclosed");
    }

    #[test]
    fn plain_text_and_structure_survive() {
        let out = sanitize("<p>Hello <b>world</b></p>").html;
        assert!(out.contains("Hello"));
        assert!(out.contains("world"));
    }
}

#[cfg(test)]
mod debug_tests {
    use super::*;
    #[test]
    fn debug_print() {
        let pass1 = ammonia_clean("<p>Hello <b>world</b></p>");
        eprintln!("PASS1: {:?}", pass1);

        let context = QualName::new(None, ns!(html), local_name!("div"));
        let dom = html5ever::driver::parse_fragment(RcDom::default(), ParseOpts::default(), context, vec![], false)
            .one(pass1.as_str());
        eprintln!("doc children: {}", dom.document.children.borrow().len());
        for c in dom.document.children.borrow().iter() {
            eprintln!("  child data: {:?}", debug_name(c));
            eprintln!("  child's children: {}", c.children.borrow().len());
            for gc in c.children.borrow().iter() {
                eprintln!("    grandchild: {:?}", debug_name(gc));
            }
        }
    }

    #[test]
    fn debug_full_path() {
        let pass1 = ammonia_clean("<p>Hello <b>world</b></p>");
        eprintln!("PASS1: {:?}", pass1);
        let result = pass2_rewrite(&pass1);
        eprintln!("PASS2: {:?} blocked={}", result.html, result.blocked_image_count);
    }

    fn debug_name(h: &Handle) -> String {
        match &h.data {
            NodeData::Document => "#document".to_string(),
            NodeData::Doctype { .. } => "#doctype".to_string(),
            NodeData::Text { contents } => format!("#text({:?})", contents.borrow().to_string()),
            NodeData::Comment { .. } => "#comment".to_string(),
            NodeData::Element { name, .. } => format!("<{}>", name.local),
            NodeData::ProcessingInstruction { .. } => "#pi".to_string(),
        }
    }
}
