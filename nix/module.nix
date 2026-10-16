{ self }: { config, lib, pkgs, ... }: let
  cfg = config.services.slopbgp;
in {
  options.services.slopbgp = {
    enable = lib.mkEnableOption "slopbgp BGP routing daemon for DN42";
    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      description = "slopbgp executable package.";
    };
    configFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Path to slopbgp configuration file (TOML or JSON).";
    };
    bgpPort = lib.mkOption {
      type = lib.types.port;
      default = 179;
      description = "BGP listening port.";
    };
    apiPort = lib.mkOption {
      type = lib.types.port;
      default = 9179;
      description = "HTTP / SSE dashboard and management API port.";
    };
    asn = lib.mkOption {
      type = lib.types.int;
      default = 4242420125;
      description = "Autonomous System Number (e.g. 4242420125).";
    };
    routerId = lib.mkOption {
      type = lib.types.str;
      default = "172.22.64.129";
      description = "BGP Router ID (IPv4 string).";
    };
  };

  config = lib.mkIf cfg.enable {
    users.users.slopbgp = {
      isSystemUser = true;
      group = "slopbgp";
      home = "/var/lib/slopbgp";
    };
    users.groups.slopbgp = {};

    systemd.services.slopbgp = {
      description = "slopbgp BGP routing daemon for DN42";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      environment = {
        SLOPBGP_DATA = "/var/lib/slopbgp";
        SLOPBGP_PORT = toString cfg.bgpPort;
        SLOPBGP_API_PORT = toString cfg.apiPort;
        SLOPBGP_ASN = toString cfg.asn;
        SLOPBGP_ROUTER_ID = cfg.routerId;
        ERL_FLAGS = "+S 4:4";
      } // (lib.optionalAttrs (cfg.configFile != null) {
        SLOPBGP_CONFIG = toString cfg.configFile;
      });
      serviceConfig = {
        User = "slopbgp";
        Group = "slopbgp";
        ExecStart = lib.getExe cfg.package;
        WorkingDirectory = "/var/lib/slopbgp";
        Restart = "on-failure";
        RestartSec = 3;
        StateDirectory = "slopbgp";
        StateDirectoryMode = "0750";
        UMask = "0027";
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" "CAP_NET_ADMIN" "CAP_NET_RAW" ];
        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" "CAP_NET_ADMIN" "CAP_NET_RAW" ];
        NoNewPrivileges = false;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectKernelTunables = false;
        ProtectControlGroups = true;
        MemoryMax = "2G";
        TasksMax = 512;
        LimitNOFILE = 16384;
      };
    };
  };
}
