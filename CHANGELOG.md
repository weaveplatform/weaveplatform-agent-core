# Changelog

## [0.9.6](https://github.com/weaveplatform/weaveplatform-agent-core/compare/v0.9.5...v0.9.6) (2026-10-05)


### Features

* **packaging:** sign and notarise the macOS package and binaries ([2707ea7](https://github.com/weaveplatform/weaveplatform-agent-core/commit/2707ea781000210f9231be9414658658861adaed))
* **packaging:** sign and notarise the macOS package and binaries ([063b6bc](https://github.com/weaveplatform/weaveplatform-agent-core/commit/063b6bcf3e4293554a4f260f5d63c57cd0571c26))


### Bug Fixes

* **packaging:** keep the keychain password apart from the p12 password ([67fd01f](https://github.com/weaveplatform/weaveplatform-agent-core/commit/67fd01f3230066b711ea50d0e95cace60014fdfa))
* **verify:** mark the codesign display call for gosec's taint check ([0adb0fb](https://github.com/weaveplatform/weaveplatform-agent-core/commit/0adb0fbd5be4441228f559b3d4838389a67db943))

## [0.9.5](https://github.com/weaveplatform/weaveplatform-agent-core/compare/v0.9.4...v0.9.5) (2026-10-04)


### Bug Fixes

* **verify:** pass the macOS code requirement to codesign inline ([b48a737](https://github.com/weaveplatform/weaveplatform-agent-core/commit/b48a7375865da6fd3b355de66653e76d92294433))
* **verify:** pass the macOS code requirement to codesign inline ([0b20517](https://github.com/weaveplatform/weaveplatform-agent-core/commit/0b205179ad3e106c632b1e819aa10c141ebcd485))

## [0.9.4](https://github.com/weaveplatform/weaveplatform-agent-core/compare/v0.9.3...v0.9.4) (2026-10-04)


### Features

* install the channel trust anchor from boot media ([3533ce3](https://github.com/weaveplatform/weaveplatform-agent-core/commit/3533ce3cd8c4beb6ba67a309d35d1ce47174e96d))
* **packaging:** macOS package and launchd daemon ([9531560](https://github.com/weaveplatform/weaveplatform-agent-core/commit/9531560e58592466b47cae812ec08e460bcafa6d))
* run weave-agent in macOS guests ([94b40c2](https://github.com/weaveplatform/weaveplatform-agent-core/commit/94b40c2d7e74c151657f4323c3814ba434e1519c))
* watch the modules directory on macOS ([5431935](https://github.com/weaveplatform/weaveplatform-agent-core/commit/543193503ce72c2f68a90c8efb6e6b4941753c09))

## [0.9.3](https://github.com/weaveplatform/weaveplatform-agent-core/compare/v0.9.2...v0.9.3) (2026-10-04)


### Features

* **packaging:** reload weave-agent through systemd ([b795897](https://github.com/weaveplatform/weaveplatform-agent-core/commit/b795897d97ed18b4ad0b4e0c52412eef5469df26))
* reload modules without restarting core ([bda42f6](https://github.com/weaveplatform/weaveplatform-agent-core/commit/bda42f6521453ef3acfb2f7fe2f837cc5d91043b))
* reload modules without restarting core ([3e06d7d](https://github.com/weaveplatform/weaveplatform-agent-core/commit/3e06d7dee466333062ec14d19ed73a824c25ae41))


### Bug Fixes

* stage module binaries on Windows so a running module never locks its install ([7265bf8](https://github.com/weaveplatform/weaveplatform-agent-core/commit/7265bf845835d13e156d151aae1d8cd542cc72d4))

## [0.9.2](https://github.com/weaveplatform/weaveplatform-agent-core/compare/v0.9.1...v0.9.2) (2026-10-04)


### Features

* module registry for core, hosts and modules ([c9f4fff](https://github.com/weaveplatform/weaveplatform-agent-core/commit/c9f4fff9c711c187e1428b2e7868ad3185449d17))
* module registry for core, hosts and modules ([53c0778](https://github.com/weaveplatform/weaveplatform-agent-core/commit/53c0778ff7090a5c43b3df62aae9efff30ae8050))

## [0.9.1](https://github.com/weaveplatform/weaveplatform-agent-core/compare/v0.9.0...v0.9.1) (2026-10-04)


### Bug Fixes

* **packaging:** create the weave-agent service account ([6893bda](https://github.com/weaveplatform/weaveplatform-agent-core/commit/6893bdabef36825a416204339d59d42fdfc8e238))
* service modules start on a stock Linux install ([455a5f5](https://github.com/weaveplatform/weaveplatform-agent-core/commit/455a5f546cdf1dd430300f9288b1d6e54cdd042c))
* stage module binaries where a service module can run them ([706aaa8](https://github.com/weaveplatform/weaveplatform-agent-core/commit/706aaa8ff761c8578d12a365cdf627cce3e2f59d))

## [0.9.0](https://github.com/weaveplatform/weaveplatform-agent-core-next/compare/v0.8.1...v0.9.0) (2026-10-03)


### Features

* weave agent core ([07fede0](https://github.com/weaveplatform/weaveplatform-agent-core-next/commit/07fede0f35d8c50e456e95d35378d02894902659))
* weave agent core ([453e7a2](https://github.com/weaveplatform/weaveplatform-agent-core-next/commit/453e7a2e944e1470704c4fd3ee1a1bbf888c51a9))


### Bug Fixes

* LF checkouts on Windows and gRPC 1.83.2 in the protocol-1 fixture ([4e6bf49](https://github.com/weaveplatform/weaveplatform-agent-core-next/commit/4e6bf496ed1448ecc44b4cf3591cb6ef5d3224e1))
