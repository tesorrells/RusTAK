use crate::helper_functions::cot_time;
use xmltree::Element;

pub fn create_cot_root_fields(
    uid: &str,
    current_time: &str,
    start_time: &str,
    stale_time_s: Option<i64>,
    cot_type: &str,
) -> Element {
    let mut root = Element::new("event");
    root.attributes
        .insert("version".to_string(), "2.0".to_string());
    root.attributes
        .insert("type".to_string(), cot_type.to_string());
    root.attributes.insert("uid".to_string(), uid.to_string());
    root.attributes.insert("how".to_string(), "m-g".to_string());
    root.attributes
        .insert("time".to_string(), current_time.to_string());
    root.attributes
        .insert("start".to_string(), start_time.to_string());
    root.attributes
        .insert("stale".to_string(), cot_time(stale_time_s).to_string());
    root
}

pub fn create_cot_point(
    latitude_deg: f64,
    longitude_deg: f64,
    altitude_m: f64,
    circular_error: f64,
    height_error: f64,
) -> Element {
    let mut point = Element::new("point");
    point
        .attributes
        .insert("lat".to_string(), latitude_deg.to_string());
    point
        .attributes
        .insert("lon".to_string(), longitude_deg.to_string());
    point
        .attributes
        .insert("hae".to_string(), altitude_m.to_string());
    point
        .attributes
        .insert("le".to_string(), height_error.to_string());
    point
        .attributes
        .insert("ce".to_string(), circular_error.to_string());
    point
}

pub fn create_cot_track(speed_over_ground: f64, course_over_ground: f64) -> Element {
    let mut track: Element = Element::new("track");
    track
        .attributes
        .insert("course".to_string(), course_over_ground.to_string());
    track
        .attributes
        .insert("speed".to_string(), speed_over_ground.to_string());
    track
}

pub fn create_cot_colors(
    fill_color: i64,
    stroke_color: i64,
    stroke_weight: i32,
) -> (Element, Element, Element) {
    let mut fill_color_element: Element = Element::new("fillColor");
    fill_color_element
        .attributes
        .insert("value".to_string(), fill_color.to_string());

    let mut stroke_color_element: Element = Element::new("strokeColor");
    stroke_color_element
        .attributes
        .insert("value".to_string(), stroke_color.to_string());

    let mut stroke_weight_element: Element = Element::new("strokeWeight");
    stroke_weight_element
        .attributes
        .insert("value".to_string(), stroke_weight.to_string());
    (
        fill_color_element,
        stroke_color_element,
        stroke_weight_element,
    )
}

pub fn create_cot_polygon(points: &Vec<(f64, f64)>) -> Vec<Element> {
    let mut element_list: Vec<Element> = Vec::new();
    for &(latitude_deg, longitude_deg) in points {
        let mut link_element: Element = Element::new("link");
        let point_value = format!("{},{},{0}", latitude_deg, longitude_deg);
        link_element
            .attributes
            .insert("point".to_string(), point_value);
        element_list.push(link_element)
    }
    element_list
}
