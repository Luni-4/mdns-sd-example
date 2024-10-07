use core::net::IpAddr;

use std::collections::HashMap;

use axum::Router;
use mdns_sd::{IfKind, ServiceDaemon, ServiceInfo};

use tracing::info;

// Service type
//
// It constitutes part of the mDNS domain.
// This also allows the firmware to be detected during the mDNS discovery phase.
const SERVICE_TYPE: &str = "_dummy";

// DNS type.
//
// It defines the mDNS type. In this case, the device is a `Dummy Device`.
const DNS_TYPE: &str = "Dummy Device";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Data which should be passed from outside
    let instance_name = "test";
    let port = 3000;

    // Initialize tracing subscriber.
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    // Create a new mDNS service daemon
    let mdns = ServiceDaemon::new()?;

    // Disable Ipv6
    mdns.disable_interface(IfKind::IPv6)?;

    // HOT SPOT: Sometimes I get conflicts in the `avahi-deamon` process
    // because I'm using the device hostname. For example,
    // if my hostname is `dummy`, it becomes `dummy-2`. I cannot understand
    // if it's the correct behaviour or some issue. I solved this problem
    // using a personal hostname, such as `luni`.
    // Retrieve the hostname associated with the machine on which the firmware
    // is running on
    let mut hostname = gethostname::gethostname().to_string_lossy().to_string();

    // Add the .local domain as hostname suffix when not present.
    //
    // .local is a special domain name for hostnames in local area networks
    // which can be resolved via the Multicast DNS name resolution protocol.

    if !hostname.ends_with(".local") {
        hostname.push_str(".local.");
    }

    hostname = "arco.local.".into();

    // HOT SPOT: I have to maintain the loopback otherwise I can only find
    // the `localhost` address.
    // Retrieve all Ipv4 interfaces associated with the device.
    //
    // Only IPv4 addresses are considered.
    let http_addresses = if let Ok(if_addresses) = if_addrs::get_if_addrs() {
        if_addresses
            .iter()
            .filter(|iface| !iface.is_loopback())
            .filter_map(|iface| {
                let ip = iface.ip();
                match ip {
                    IpAddr::V4(_) => Some(ip),
                    _ => None,
                }
            })
            .collect::<Vec<IpAddr>>()
    } else {
        Vec::new()
    };

    // HOT SPOT: I cannot use &'static str but only String to define properties.
    // Would it be possible to define a `Cow<'static>` type?
    // Defines properties.
    let mut properties: HashMap<String, String> = HashMap::new();
    // Scheme
    properties.insert("scheme".into(), "http".into());
    // Device DNS type
    properties.insert("type".into(), DNS_TYPE.into());

    // Define mDNS domain
    let domain = format!("{SERVICE_TYPE}._tcp.local.");

    info!("Service instance name: {}", instance_name);
    info!("Service domain: {domain}");
    info!("Service port: {}", port);
    info!("Service addresses: {:?}", http_addresses);
    info!(
        "Device reachable at this hostname: {}:{}",
        &hostname[0..hostname.len() - 1],
        port
    );

    let service = ServiceInfo::new(
        // Domain label and service type
        &domain,
        // Service instance name
        instance_name,
        // DNS hostname.
        //
        // For the same hostname in the same local network, the service resolves
        // in the same addresses. It is used for A (IPv4) and AAAA (IPv6)
        // records.
        &hostname,
        // Considered IP address which allow to reach out the service.
        "",
        // Port on which the service listens to. It has to be same of the
        // server.
        port,
        // Service properties
        properties,
    )?
    .enable_addr_auto();

    mdns.register(service)?;

    // Create listener bind.
    let listener_bind = format!("{}:{}", http_addresses[0], port);

    // Print server Ip and port.
    info!("Server reachable at this HTTP address: {listener_bind}");

    // Create router.
    let router = Router::new().route(
        "/",
        axum::routing::get(move || async { "This the main page!" }),
    );

    // Create a new TCP socket which responds to the specified HTTP address
    // and port.
    let listener = tokio::net::TcpListener::bind(listener_bind).await?;

    // Print server start message
    info!("Starting server...");

    // Start the server
    axum::serve(listener, router).await?;

    Ok(())
}
