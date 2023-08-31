use std::collections::HashMap;
use xmltree::Element;

pub fn create_cot_atom_message(
    callsign: &str,
    mut root: Element,
    point: Element,
    track: Element,
    uid_list: HashMap<String, String>,
) -> Element {
    let mut uid_entity = Element::new("uid");
    // This won't compile without the to_string - mismatched types expected `String`, found `&String`
    for (uid_key, uid_val) in uid_list.iter() {
        uid_entity
            .attributes
            .insert(uid_key.to_string(), uid_val.to_string());
    }
    root.children.push(xmltree::XMLNode::Element(point));

    let mut contact = Element::new("contact");
    contact
        .attributes
        .insert("callsign".to_string(), callsign.to_string());

    let mut detail = Element::new("detail");
    detail.children.push(xmltree::XMLNode::Element(contact));
    detail.children.push(xmltree::XMLNode::Element(track));
    detail.children.push(xmltree::XMLNode::Element(uid_entity));

    root.children.push(xmltree::XMLNode::Element(detail));
    root
}

pub fn create_cot_polygon_message(
    callsign: &str,
    mut root: Element,
    point: Element,
    polygon: Vec<Element>,
    polygon_color: (Element, Element, Element),
) -> Element {
    root.children.push(xmltree::XMLNode::Element(point));

    let mut contact = Element::new("contact");
    contact
        .attributes
        .insert("callsign".to_string(), callsign.to_string());

    let mut detail = Element::new("detail");

    for link in polygon {
        detail.children.push(xmltree::XMLNode::Element(link));
    }

    detail.children.push(xmltree::XMLNode::Element(contact));
    detail
        .children
        .push(xmltree::XMLNode::Element(polygon_color.0));
    detail
        .children
        .push(xmltree::XMLNode::Element(polygon_color.1));
    detail
        .children
        .push(xmltree::XMLNode::Element(polygon_color.2));

    root.children.push(xmltree::XMLNode::Element(detail));
    root
}
