use crate::helper_functions::cot_time;
use xmltree::Element;

/// Creates the root `<event>` element for a CoT message with common attributes.
///
/// # Arguments
/// * `uid`: The unique ID for the CoT event.
/// * `current_time`: The current time string (e.g., from `cot_time(None)`).
/// * `start_time`: The start time string (e.g., from `cot_time(None)`).
/// * `stale_time_s`: An optional number of seconds from now when the event becomes stale.
///   The actual stale timestamp will be calculated using `cot_time()`.
/// * `cot_type`: The CoT type string (e.g., "a-f-G-E-V-C").
///
/// # Returns
/// An `xmltree::Element` representing the CoT event root.
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

/// Creates a CoT `<point>` element.
///
/// # Arguments
/// * `latitude_deg`: Latitude in decimal degrees.
/// * `longitude_deg`: Longitude in decimal degrees.
/// * `altitude_m`: Height Above Ellipsoid (HAE) in meters.
/// * `circular_error`: Circular Error (CE) in meters.
/// * `height_error`: Linear Error (LE) for height, in meters.
///
/// # Returns
/// An `xmltree::Element` representing the CoT point.
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

/// Creates a CoT `<track>` element.
///
/// # Arguments
/// * `speed_over_ground`: Speed over ground, typically in knots but the unit isn't enforced by this primitive.
///   CoT standard often implies m/s, but TAK clients might interpret based on context or preferences.
/// * `course_over_ground`: Course over ground in decimal degrees from True North.
///
/// # Returns
/// An `xmltree::Element` representing the CoT track.
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

/// Creates CoT color elements: `<fillColor>`, `<strokeColor>`, and `<strokeWeight>`.
///
/// Colors are typically ARGB (Alpha, Red, Green, Blue) integer values.
///
/// # Arguments
/// * `fill_color`: ARGB integer for the fill color.
/// * `stroke_color`: ARGB integer for the stroke color.
/// * `stroke_weight`: The weight (thickness) of the stroke.
///
/// # Returns
/// A tuple containing three `xmltree::Element`s: (`fillColor`, `strokeColor`, `strokeWeight`).
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

/// Creates a CoT `<shape>` element containing a `<polyline>` with `<vertex>` children.
///
/// Used for representing polygons or polylines.
///
/// # Arguments
/// * `points`: A slice of tuples, where each tuple is `(latitude_deg, longitude_deg, hae_m)`.
/// * `closed`: A boolean indicating if the polyline should be closed (forming a polygon).
///
/// # Returns
/// An `xmltree::Element` representing the CoT shape with its polyline.
pub fn create_cot_polygon_shape(points: &[(f64, f64, f64)], closed: bool) -> Element {
    let mut shape_element = Element::new("shape");
    let mut polyline_element = Element::new("polyline");
    polyline_element
        .attributes
        .insert("closed".to_string(), closed.to_string());

    for (lat, lon, hae) in points {
        let mut vertex_element = Element::new("vertex");
        vertex_element
            .attributes
            .insert("point".to_string(), format!("{},{},{}", lat, lon, hae));
        polyline_element
            .children
            .push(xmltree::XMLNode::Element(vertex_element));
    }
    shape_element
        .children
        .push(xmltree::XMLNode::Element(polyline_element));
    shape_element
}
