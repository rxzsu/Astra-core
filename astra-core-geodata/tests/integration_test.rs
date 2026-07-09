use astra_core_geodata::GeoDataManager;

fn test_data_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("target")
        .join(name)
}

#[test]
fn test_load_real_geoip() {
    let path = test_data_path("test-geoip.dat");
    if !path.exists() {
        eprintln!("skipping real geoip test (file not found)");
        return;
    }
    let mut mgr = GeoDataManager::new();
    mgr.load(&path).expect("should load geoip.dat");
    assert!(!mgr.geoip.is_empty(), "should have at least one country");

    if let Some(cn) = mgr.geoip.get("CN") {
        assert!(!cn.cidr.is_empty(), "CN should have CIDR entries");
        eprintln!("CN has {} CIDR entries", cn.cidr.len());
    }
}

#[test]
fn test_load_real_geosite() {
    let path = test_data_path("test-geosite.dat");
    if !path.exists() {
        eprintln!("skipping real geosite test (file not found)");
        return;
    }
    let mut mgr = GeoDataManager::new();
    mgr.load(&path).expect("should load geosite.dat");
    assert!(!mgr.geosite.is_empty(), "should have at least one category");

    if let Some(google) = mgr.geosite.get("GOOGLE") {
        assert!(
            !google.domains.is_empty(),
            "GOOGLE should have domain entries"
        );
        eprintln!("GOOGLE has {} domain entries", google.domains.len());
        for d in google.domains.iter().take(5) {
            eprintln!("  type={} value={}", d.r#type, d.value);
        }
    }
}
