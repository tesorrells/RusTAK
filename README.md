# RusTAK

RusTAK is a simple wrapper for using Rust to interact with ATAK, WinTAK, TAK Server, and other TAK enabled products. It includes simple functions to initiate network connections via UDP, TCP, and TCP/TLS that users can communicate with via a multiprocessing queue to send and receive data from a network connection.

Currently only cursor-on-target (CoT) is supported, but TAK Protobuf will be implemented in a future release. 

### Network Functions
udp_sender - takes in a SocketAddr and a multiprocessing receiver to receive CoT from your mainline program and send CoT to the network end point.

udp_receiver - takes in a port to bind and a multiprocessing sender to receive CoT from the UDP port and relay it to your mainline program.

tcp_sender - takes in a SocketAddr and a multiprocessing receiver to receive CoT from your mainline program and send CoT to the network end point.

tcp_receiver - takes in a SocketAddr and a multiprocessing sender to to receive CoT from the TCP address and port and relay it to your mainline program.

tls_sender - takes in a SocketAddr, a multiprocessing receiver, and a cafile for TLS cert information to receive CoT from your mainline program and send CoT to the network end point.

tls_receiver - takes in a SocketAddr, a multiprocessing sender, and a cafile for TLS cert information to to receive CoT from the TCP address and port and relay it to your mainline program.


### CoT Functions
#### Primitives
create_cot_root_fields - takes in the uid of the CoT message, the current time, the start time, the stale time, and finally the CoT type, defined in cot_types.xml to create the root xml node for a CoT message

create_cot_point - takes in a latitude and longitude in degrees, an altitude in meters, and a circular and height error in decimal to create the point xml field for the location of a track.

create_cot_track - takes in speed over ground in knots and course over ground in degrees to create the track xml field for the vector of a track.

create_cot_colors - takes in fill and stroke color, along with stroke weight to build the xml color fields used to color CoT polygons.

create_cot_polygon - takes in a vector of latitude and longitude tuples to build the xml structure of the CoT polygon.

#### Builders
create_cot_atom_message - takes in a callsign to display, along with the root node, a point node, a track node, and a hashmap of string to string to identify the associated uids for a given track to build a complete CoT atom message to send to a TAK end point.

create_cot_polygon_message - takes in a callsign to display, along with a root node, a point node, a polygon vector, and a polygon color tuple to build a complete CoT polygon message to send to a TAK end point.