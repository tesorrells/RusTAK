use std::collections::HashMap;
use xmltree::Element;

/// Assembles a complete CoT "atom" message (typically a point feature like a friendly unit).
///
/// This function takes pre-constructed CoT elements (root, point, track) and combines them
/// with a callsign and UID information to form a standard CoT presence message.
///
/// # Arguments
/// * `callsign`: The callsign to be used in the `<contact>` element.
/// * `root`: The base `<event>` element, typically created by `create_cot_root_fields`.
///   This element will be modified by adding child elements.
/// * `point`: The `<point>` element for the CoT message.
/// * `track`: The `<track>` element (course and speed) for the CoT message.
/// * `uid_list`: A `HashMap` for attributes of the `<uid>` element (e.g., Droid, Medusa UIDs).
///
/// # Returns
/// An `xmltree::Element` representing the complete CoT atom message.
pub fn create_cot_atom_message(
    callsign: &str,
    mut root: Element,
    point: Element,
    track: Element,
    uid_list: HashMap<String, String>,
) -> Element {
    let mut uid_entity = Element::new("uid");
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

/// Assembles a complete CoT message for a polygon feature.
///
/// This function takes pre-constructed CoT elements (root, point, shape, colors)
/// and combines them with a callsign to form a CoT message representing a polygon.
///
/// # Arguments
/// * `callsign`: The callsign to be used in the `<contact>` element.
/// * `root`: The base `<event>` element, typically created by `create_cot_root_fields`.
///   This element will be modified by adding child elements.
/// * `point`: The `<point>` element, often representing the centroid or a label point for the polygon.
/// * `polygon_shape`: The `<shape>` element containing the polygon geometry, created by `create_cot_polygon_shape`.
/// * `polygon_color`: A tuple of three `Element`s (`fillColor`, `strokeColor`, `strokeWeight`),
///   typically created by `create_cot_colors`.
///
/// # Returns
/// An `xmltree::Element` representing the complete CoT polygon message.
pub fn create_cot_polygon_message(
    callsign: &str,
    mut root: Element,
    point: Element,
    polygon_shape: Element,
    polygon_color: (Element, Element, Element),
) -> Element {
    root.children.push(xmltree::XMLNode::Element(point));

    let mut contact = Element::new("contact");
    contact
        .attributes
        .insert("callsign".to_string(), callsign.to_string());

    let mut detail = Element::new("detail");

    detail
        .children
        .push(xmltree::XMLNode::Element(polygon_shape));

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
