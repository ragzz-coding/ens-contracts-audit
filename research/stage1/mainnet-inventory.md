# Mainnet inventory @ v1.7.0

Analysis commit: `9b034936a42f462fc04bc0a929a419ede5e18d59`  
Sources: tag artifacts `deployments/mainnet/*.json` + [ENS Contract Deployments wiki](https://github.com/ensdomains/ens-contracts/wiki/ENS-Contract-Deployments)

| Contract | Mainnet address | Wiki↔Tag | Sourcify runtime | Raw artifact↔chain |
|---|---|---|---|---|
| ArbitrumReverseResolver | `0x4b9572C03AAa8b0Efa4B4b0F0cc0f0992bEDB898` | exact | exact_match | DIFF_LIKELY_IMMUTABLES |
| BaseRegistrarImplementation | `0x57f1887a8BF19b14fC0dF6Fd9B2acc9Af147eA85` | exact | match | NO_ARTIFACT_BYTECODE |
| BaseReverseResolver | `0xc800DBc8ff9796E58EfBa2d7b35028DdD1997E5e` | exact | exact_match | DIFF_LIKELY_IMMUTABLES |
| BatchGatewayProvider | `0xd1E3FAc3837b85437530B8B5244E4deF43219C04` | exact | exact_match | EXACT_HEX |
| DNSRegistrar | `0xB32cB5677a7C971689228EC835800432B339bA2B` | exact | exact_match | DIFF_LIKELY_IMMUTABLES |
| DNSSECImpl | `0x0fc3152971714E5ed7723FAFa650F86A4BaF30C5` | exact | exact_match | EXACT_HEX |
| DefaultReverseRegistrar | `0x283F227c4Bd38ecE252C4Ae7ECE650B0e913f1f9` | exact | exact_match | EXACT_HEX |
| DefaultReverseResolver | `0xA7d635c8de9a58a228AA69353a1699C7Cc240DCF` | exact | exact_match | DIFF_LIKELY_IMMUTABLES |
| ENSRegistry | `0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e` | exact | match | NO_ARTIFACT_BYTECODE |
| ETHRegistrarController | `0x59E16fcCd424Cc24e280Be16E11Bcd56fb0CE547` | exact | exact_match | DIFF_LIKELY_IMMUTABLES |
| ExponentialPremiumPriceOracle | `0x7542565191d074cE84fBfA92cAE13AcB84788CA9` | exact | exact_match | DIFF_LIKELY_IMMUTABLES |
| ExtendedDNSResolver | `0x08769D484a7Cd9c4A98E928D9E270221F3E8578c` | exact | exact_match | EXACT_HEX |
| LineaReverseResolver | `0x0Ce08a41bdb10420FB5Cac7Da8CA508EA313aeF8` | exact | exact_match | DIFF_LIKELY_IMMUTABLES |
| MigrationHelper | `0xeA6407e845Bf7a462FBdb3584728a9f617dA7FE9` | exact | exact_match | DIFF_LIKELY_IMMUTABLES |
| NameWrapper | `0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401` | exact | exact_match | DIFF_LIKELY_IMMUTABLES |
| OffchainDNSResolver | `0xF142B308cF687d4358410a4cB885513b30A42025` | exact | exact_match | DIFF_LIKELY_IMMUTABLES |
| OptimismReverseResolver | `0xF9Edb1A21867aC11b023CE34Abad916D29aBF107` | exact | exact_match | DIFF_LIKELY_IMMUTABLES |
| P256SHA256Algorithm | `0xb091c4f6fac16edda5ee1e0f4738f80011905878` | exact | exact_match | EXACT_HEX |
| PublicResolver | `0xF29100983E058B709F3D539b0c765937B804AC15` | exact | exact_match | DIFF_LIKELY_IMMUTABLES |
| RSASHA1Algorithm | `0x58e0383e21f25dab957f6664240445a514e9f5e8` | exact | exact_match | EXACT_HEX |
| RSASHA256Algorithm | `0xaee0e2c4d5ab2fc164c8b0cc8d3118c1c752c95e` | exact | exact_match | EXACT_HEX |
| RegistrarSecurityController | `0x7dd4d97653a67c2fd7fba0a84825ec09524d4e1b` | exact | exact_match | EXACT_HEX |
| ReverseRegistrar | `0xa58E81fe9b61B5c3fE2AFD33CF304c454AbFc7Cb` | exact | exact_match | DIFF_LIKELY_IMMUTABLES |
| Root | `0xaB528d626EC275E3faD363fF1393A41F581c5897` | exact | match | NO_ARTIFACT_BYTECODE |
| RootSecurityController | `0x95123b1ec97df0d3c52c728ab38fbbb7a3ca6da6` | exact | exact_match | EXACT_HEX |
| SHA1Digest | `0x9c9fcEa62bD0A723b62A2F1e98dE0Ee3df813619` | exact | exact_match | EXACT_HEX |
| SHA1NSEC3Digest | `0x849851A7683cfF52De5F50C712C0606FEf6A3e8f` | exact | exact_match | EXACT_HEX |
| SHA256Digest | `0xCFe6edBD47a032585834A6921D1d05CB70FcC36d` | exact | exact_match | EXACT_HEX |
| ScrollReverseResolver | `0xC4842814cA523E481Ca5aa85F719FEd1E9CaC614` | exact | exact_match | DIFF_LIKELY_IMMUTABLES |
| SimplePublicSuffixList | `0x823BDa9cA8c47d072376eCD595530c8fb2fAa3ED` | exact | exact_match | EXACT_HEX |
| StaticBulkRenewal | `0xc649947a460B135e6B9a70Ee2FB429aDBB529290` | exact | exact_match | EXACT_HEX |
| StaticMetadataService | `0x3A368e3D5F19aF3DE594A9fC2CFfc6e256a616c7` | exact | exact_match | EXACT_HEX |
| TLDPublicSuffixList | `0x7A72fEFd970A7726c4823623d88E9f3eFA1c300C` | exact | exact_match | EXACT_HEX |
| UniversalResolver | `0xED73a03F19e8D849E44a39252d222c6ad5217E1e` | exact | exact_match | DIFF_LIKELY_IMMUTABLES |
| WrappedETHRegistrarController | `0x253553366Da8546fC250F225fe3d25d0C782303b` | exact | exact_match | DIFF_LIKELY_IMMUTABLES |

`DIFF_LIKELY_IMMUTABLES`: artifact `deployedBytecode` length matches chain code, but constructor-injected immutable slots are zero in the artifact and populated on-chain (verified on `ETHRegistrarController`). Sourcify remains the binding match.
