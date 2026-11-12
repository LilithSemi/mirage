{
  lib,
  stdenv,
  flakever,
  zig,
  mkShell,
}:
stdenv.mkDerivation (finalAttrs: {
  pname = "mirage";
  inherit (flakever) version;

  src = lib.cleanSource ../../.;

  zigDeps = zig.fetchDeps {
    inherit (finalAttrs) src pname version;
    hash = "sha256-5fq0AbGxyc5OEQdSIPzPSqHnruP9sShKNWy7UVtrmrc=";
  };

  nativeBuildInputs = [
    zig
  ];

  postConfigure = ''
    ln -s ${finalAttrs.zigDeps} "$ZIG_GLOBAL_CACHE_DIR/p"
  '';

  doCheck = true;

  passthru.shell = mkShell {
    name = "mirage-dev-shell";
    packages = [
      zig
    ];
  };
})
