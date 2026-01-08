# SPRK-Chat

- Experimental ... 

> tools/pqsig_keygen.cpp to generate keys, see tools/readme.md to build liboqs.

(LLM GENERATED README)

# SPRK-Chat

**Experimental Post-Quantum Secure End-to-End Encrypted Chat**


## Strengths — What It Gets Right

- **End-to-end encrypted messages** using symmetric AEAD derived from ML-KEM (Kyber) shared secrets
- **Post-quantum key exchange** (ML-KEM via liboqs)
- **Post-quantum digital signatures** (ML-DSA) for long-term identity authentication
- **Forward secrecy** via automatic ephemeral rekeying (~every 1024 messages)
- Replay protection with per-sender sequence numbers, jitter tolerance, and gap checks
- Rate limiting (100 msgs/sec per client) and stale message timeouts (60s)
- Username validation and similarity checks to reduce confusion attacks
- Sender fingerprints (SHA-256 of long-term public key) displayed with every message
- Clean, readable codebase with modern C++ features and CMake build system
- No server-side message persistence

These features provide strong protection against **passive eavesdropping**, **message tampering**, **replays**, and **future quantum decryption attacks** (harvest-now-decrypt-later).

## Weaknesses — Important Limitations

This is an **experimental prototype with no security audit**. Do **not** use it for sensitive or private communications without understanding the risks.

### Critical Technical Weaknesses
- **Unauthenticated initial handshake (TOFU — Trust On First Use)**  
  The first key exchange and identity binding occur without prior authenticated channel.  
  An **active man-in-the-middle attacker** who intercepts and modifies traffic **during the initial handshake** can impersonate participants by substituting their own long-term keys and relay all subsequent traffic undetected.  
  Once the legitimate handshake completes, later messages remain securely E2E-encrypted and an attacker cannot insert themselves.  
  → **Mitigation**: Manually verify fingerprints or safety numbers with chat partners on first contact (e.g., via voice call or another channel).

- **No built-in transport encryption**  
  All traffic runs over plain TCP:  
  - Metadata (IP addresses, timestamps, message sizes, fingerprints, session IDs) is visible to anyone on the network path **throughout the entire session**.  
  - An active attacker can perform the above MITM impersonation attack **only if they control the initial handshake**.  
  → For metadata protection and handshake integrity, run the server behind stunnel, a TLS-terminating reverse proxy (e.g., Nginx with post-quantum TLS), or similar.

- **No formal security audit or third-party review**  
  Custom protocol and crypto integration carry a high risk of subtle implementation bugs.

## Build & Run

### Dependencies
- liboqs (Open Quantum Safe)
- OpenSSL ≥ 3.0
- CMake ≥ 3.20
- C++23-capable compiler (g++/clang++)

Detailed liboqs build instructions are in `tools/readme.md`.


### Building
```bash
./scripts/build.sh
```

### SERVER
```
$ /home/mmmm/Desktop/SPRK_DEV_TIDY/bin/server 1566
connect ron session=yBiaFexrr7bXgTM2PB7SjjpiLdTEUQSWSxwhqAxr6GkT3KMeZcB1VskUBQhn
connect beth session=yBiaFexrr7bXgTM2PB7SjjpiLdTEUQSWSxwhqAxr6GkT3KMeZcB1VskUBQhn
connect ron session=yBiaFexrr7bXgTM2PB7SjjpiLdTEUQSWSxwhqAxr6GkT3KMeZcB1VskUBQhn
connect bob session=yBiaFexrr7bXgTM2PB7SjjpiLdTEUQSWSxwhqAxr6GkT3KMeZcB1VskUBQhn
connect ron session=yBiaFexrr7bXgTM2PB7SjjpiLdTEUQSWSxwhqAxr6GkT3KMeZcB1VskUBQhn
connect beth session=yBiaFexrr7bXgTM2PB7SjjpiLdTEUQSWSxwhqAxr6GkT3KMeZcB1VskUBQhn
disconnect bob session=yBiaFexrr7bXgTM2PB7SjjpiLdTEUQSWSxwhqAxr6GkT3KMeZcB1VskUBQhn
connect bob session=yBiaFexrr7bXgTM2PB7SjjpiLdTEUQSWSxwhqAxr6GkT3KMeZcB1VskUBQhn
connect beth session=yBiaFexrr7bXgTM2PB7SjjpiLdTEUQSWSxwhqAxr6GkT3KMeZcB1VskUBQhn
connect ron session=yBiaFexrr7bXgTM2PB7SjjpiLdTEUQSWSxwhqAxr6GkT3KMeZcB1VskUBQhn
disconnect bob session=yBiaFexrr7bXgTM2PB7SjjpiLdTEUQSWSxwhqAxr6GkT3KMeZcB1VskUBQhn
connect bob session=yBiaFexrr7bXgTM2PB7SjjpiLdTEUQSWSxwhqAxr6GkT3KMeZcB1VskUBQhn
connect ron session=yBiaFexrr7bXgTM2PB7SjjpiLdTEUQSWSxwhqAxr6GkT3KMeZcB1VskUBQhn
connect beth session=yBiaFexrr7bXgTM2PB7SjjpiLdTEUQSWSxwhqAxr6GkT3KMeZcB1VskUBQhn


```

### CLIENT 1
```
$ /home/mmmm/Desktop/SPRK_DEV_TIDY/bin/client 127.0.0.1 1566 ron /home/mmmm/Desktop/ssh/output.sk
Created session: yBiaFexrr7bXgTM2PB7SjjpiLdTEUQSWSxwhqAxr6GkT3KMeZcB1VskUBQhn
[1767658434976] connected
[01:14:11] connect beth pubkey=d0fa83a7be...b1f18f9fa9
[01:14:25] connect bob pubkey=7231448d05...507bfb5bdb
list users
users:
bob [87fab05a438a721b73233df03cb60655319456b57241e3c481ba489ceed28099]
beth [7556c04652e0e852f67cbfd2337f33d3e6c86bcb298c2040bc28a0238d53354a]
ron [5e2da901c732f40b7b1466f573afd8b9d843cb990aab1021dac7daaa20023c58]
[01:15:57] [beth 7556c04652] hey ron
7556c04652e0e852f67cbfd2337f33d3e6c86bcb298c2040bc28a0238d53354a ditto
[01:16:11] [beth 7556c04652] "ditto"
87fab05a438a721b73233df03cb60655319456b57241e3c481ba489ceed28099 hello bob
[01:16:27] [bob 87fab05a43] "hello bob"
[01:16:44] [bob 87fab05a43] :)
[1767658618376] peer bob rekeyed
[01:16:58] connect bob pubkey=7231448d05...507bfb5bdb
[01:17:21] [bob 87fab05a43] 7556c04652e0e852f67cbfd2337f33d3e6c86bcb298c2040bc28a0238d53354a back
[1767658656873] peer bob rekeyed
[01:17:36] connect bob pubkey=7231448d05...507bfb5bdb
[01:17:48] [bob 87fab05a43] back

```

### CLIENT 2
- join session created by client 1
```
$  /home/mmmm/Desktop/SPRK_DEV_TIDY/bin/client 127.0.0.1 1566  beth /home/mmmm/Desktop/ssh/output1.sk --sessionid yBiaFexrr7bXgTM2PB7SjjpiLdTEUQSWSxwhqAxr6GkT3KMeZcB1VskUBQhn
[1767658451505] connected
[01:14:11] connect ron pubkey=97f4ba3f29...2a82f2daf4
[1767658451506] INFO: awaiting encaps from ron
[01:14:11] connect ron pubkey=97f4ba3f29...2a82f2daf4
[01:14:25] connect bob pubkey=7231448d05...507bfb5bdb
list users
users:
bob [87fab05a438a721b73233df03cb60655319456b57241e3c481ba489ceed28099]
beth [7556c04652e0e852f67cbfd2337f33d3e6c86bcb298c2040bc28a0238d53354a]
ron [5e2da901c732f40b7b1466f573afd8b9d843cb990aab1021dac7daaa20023c58]
87fab05a438a721b73233df03cb60655319456b57241e3c481ba489ceed28099 hey bob
[01:14:53] [bob 87fab05a43] "hey bob"
[01:15:10] [bob 87fab05a43] good day beth
pubk 87fab05a438a721b73233df03cb60655319456b57241e3c481ba489ceed28099
pubkey 87fab05a438a721b73233df03cb60655319456b57241e3c481ba489ceed28099 
7231448d05fdbefa15229734369f902482e39c977bf0768ce35b2a2342a93374d65cfefb2336c177e5536584fdf7d4bc36f83802b9eed977a438436a27b24e067956baa3f8f9c40b755db9eebedcb31c1d159f295727e02e52c9ae54c7aea42b9e662bbec50fdb613b7de3507beb3425101d9644c44ec20ac55f07a5a7aa7ade6dc885daa4f4f79bf5e5c231a716a3dffd76b03dec5a60947c30afc845fa01bf3b2e7be835f6eb50ef9d4da7607487e5507581376d262556735b78e6e3353861f1c6ad65621d530f872077d543137fecce3f961b23ff37614f1aca75eaf70e66454b858e3089abd06c9fb454a4db8441e71777249bbef7998b32d3b5c947bde5bc230630861f9db300bcd278e573d36d3a11ab76b84b7bc57625620a814ba9db3e3b6b944f1ad254826260ffc135955f248306c5d96d097ac24cdb50cbcf4951d048727aae39091e2c5ad4c0283163f607faf1b0fdc0164c0589712a3e847b2a3297218aaad1f684f306c9db04d998650ac3adfa26ef9eb9a1a37f4b6acfc6ec9dbf90edbfec9864ec821febdc7b85fb41ee3184a68276df1aed4608b972c3913b5977778fc3adc956ed4ba38b222e44397715f266f5dc0686fe250606dd855d3a8f8f6fb3a1d5f0e36d6cc28a87094e4de3ba1aaaa2bd9b14ec938735c67c44ecef928b10fa17deac783b5d28918148598b3514ef42f6c0120ab702372630a3ac1f59057df744c33cd3c3735d9769b5db5084939fa52534421670d5c2aa51e8c8bdfe66562f5722511bec81ab5b3cc007973c6431c8f06d594612470faebec09b5d0106fcd74b0786c4cc394ba5691a6c00deaad4b96e24b9cc42821339ef83884fcbc969802ff3a0f1275e331820795be194f284ea0a0838e7a54cc0bdd535be25a5b4d29b98415edc21978641d642eb6737573f4d33494e02b44ea1981837ad3c84dff665fb376c64cf11a597c4fa5ce8dfbd63e7ecfb9ec9edca150dccce00e917a706b65e79ca05d661773a0a0b97289009a2d78a78aeafdfe01a950eee23db61343c574daf81498132aa062933309ec3727f312c9b01144fd971a4970f5163ad39618e803a40a6d07e1101a5582133727f2fc4b491ed3537e958f42d96e67800e6d0b73d44d65a3a1ff8972a40103a4f1709dbd8f333945a1ac658f53fbbeefe366945c238e634417b293a4a31f1df89a8f3b0926a4cc2eb916f978d11e9d58623b6331746b862651147f059213d51d250c3ac54e4ea16ed9cabd0c1f7b6fa302978d24c23e256c8d0716be3bc8ca0db1eac56c7e99a02a76b84451f7ddd667ec766041eeff08155cfbf696036a46932596778677fbf2ec3057080ef20ebc90ec09662db620e529a9b650b613ccada0c619e0d8ffe3365202a6006e0727d983d9cfa533af829378cc1ede0d955952fcd705f3ac338c0f48d368e47b18ba698aa9e19e17c2eeb4904752c1aa6ea3a2a5067dfe34931a27c0e606927baa81fbc476b85129655324327b77aee0f4436d69ef9b96c36d657e0140c3c148f57d5ccb5df86211538b83c42be417102ba1a64d9a4b5a7d89c4c2caa86489013d5d85989ad46ef2cdc0ddf5029e761aa6498c045407173b23e89295ed1f106e811dddfdf5ed6f0a9ff8de4743284ba37aba44d50efc28ed9ba3ccec5ebe5248bbfe53a43a26644d30786e6ce5c1e8160a7170aa764c75c47f94b2418937ed53d58f0aa675be186c8023cfea5708f2ac6250c72224b4a03d2d759125627a5ae0d09a60631c8f575243bdf052f563d3cb8be15c47f4e38eb367e6bd9d9589ab762f79063d422b9dccb58593a7a75ba14c849182b747001e3d8a9299666a951e30ce7249ab0064b7e8a57a87548b692bccf4961a877ac6e9a77c424ba9c490ccfeb435198cbd3a3e766c063e96261bdefe0a76cbfded79b6718cb04b5969e637bc7f7343dcc8d2309982331222af9bd2c20a367de8d1bf012d02534b534dfa71476b74c6e143f2b2855840d013ed6d1c0e228c0e24221c399e71eb5e4ff9a770632a7255b27a6501ecdde42c07153a1296d1a0575b92dabc55c5ab5ca64f8407f5d6d7fec8012b7ebb4c0afecec4ea433ee6762d98a669a36feeceef48dc70af7a9bc8d1dc480427f3fe7fc58fabad5f4bbe4f8f2bc78133e399cc600115877216518b890c510439232f16a8768e1c6b892df38c0e114a8c05d01a8380bb12b068516d1784e7b887e2069a7497221c877651a34a60889117a4fb7ade86c6183394ec1a36e329661caa377addd70e6154f29cb6e11936da3517e9d327183b016f1fa7409c4b349aeb63cc50d36c89e9c06e71042b314231190f772f035af678ee7d0ee873f52b9ba534485c82f7751aa14e7e4b2622f17820bcc79e0c0d20491b0dccecb1ea426d3fdbbbc626497a15ea755fa2a0df64863a8b778825044cceb4a9f111b493b33363e4f38a7093225317f53a358b5b54eab2b5a6f4854ad8b56d9df4bcc9c810d0fd8699bf420775b0a3bfe014a5f0cfd04f4f1ac38f03862a1de3b9f005f059d679a3bf24544b0441a77638eb87502eae6bacb85c82d9820b38b3ee4b6df8f219c819f44ae49c16158dcd974292cdb5e5cf93d3214e675408b68803a8d51970841d17afe3dcc6328174ea535e35a5bfa07182691b27ff24526400fcf1b52f6069563f4faf48f9112a5c48c5fb305b0ec9236f161081ddab2c74a00a00d78b379756b36c2eeb15b99a151d43ae20ac6de47890a76d64d4d0b1b8d178799f667934f1321085aacd6973653575edf3758f2b047a7ff954d4f5f00d587f09cdc11857ee7f9b34a0f5a9185fd817dfc2e4fff6ae34c67715c2852b28d7eb7120370d1323d711458ce232f6133fca3301bbeca11b9eda5ea12bd9edff57fd4ce72538ce7b907b11f59da34747a90e63cbae02c8e36a507ddf3364e0b8370bf91e1f253d3420d9d05fa4167acbab9d993002ec7f1efaca0007b5a518528aa2094ec560be3b9deafcbd85ecd9b75854c7a3908c4c6c56b6ffd0f6e404bf804b7eafd2bbdc28c023da48713be29ed4c1d8ba5a92930cbfdb5e945dcccda155b79e41c6ffa1e6770afdcb73126db4a6164192aea318347a81c0913291e543076ff6865879f2d8be175d6539c472cb86f19149ab271c0a3f634b4a298694c761f741c16560fe8e21c280dd4343559f52c08f6bfd10ce2b8732ba41bbd0f782a35fb8df6ba6bc97befa6289c3b75339f4804540087c546aa5f9378cc38a164dd73d525639e6fccb4d5adfcb9902f6fd86b8570f50ef7aa4cf8a21a24ede126420c3dc4d09ab453497c126d50e5e0f9024e731c5665112d7bcdbfbaffeece4b2bd5611314fca9ff01380fa62dca4f1e5b594fc6a32010efb83508a18093257d2792a4984d185763f829d8a6d1a600d8f08783eb390d415665ae4e375e40586b08fba9d0eb81ffc7655eefb1d3d9bdcfb8db0758c758b17699b9495fc863be72738dc568dbff7b7ae0cc769b67316b24fc65b5d1bf53872f824a6e252af871f684ddce7c31bb1fe847c298c47e3a143d02bb0793e1524eaae50650c39e42fa0b56a06d91c8ad327438c94e8ef0bc3f5bb3aefeea99afbcbeff72a8e12505f7b4e60aa5790b8b9719d0e74e1996b8abdd36090dfed9ccb72f3472d798b398507bfb5bdb
5e2da901c732f40b7b1466f573afd8b9d843cb990aab1021dac7daaa20023c58 hey ron
[01:15:57] [ron 5e2da901c7] "hey ron"
[01:16:11] [ron 5e2da901c7] ditto
[1767658618376] peer bob rekeyed
[01:16:58] connect bob pubkey=7231448d05...507bfb5bdb
[1767658656873] peer bob rekeyed
[01:17:36] connect bob pubkey=7231448d05...507bfb5bdb
[01:18:03] [bob 87fab05a43] back


```
### CLIENT 3
```
$ /home/mmmm/Desktop/SPRK_dev/bin/client 127.0.0.1 1566  bob /home/mmmm/Desktop/ssh/output2.sk --sessionid yBiaFexrr7bXgTM2PB7SjjpiLdTEUQSWSxwhqAxr6GkT3KMeZcB1VskUBQhn
[1767658465173] connected
[01:14:25] connect beth pubkey=d0fa83a7be...b1f18f9fa9
[1767658465174] INFO: awaiting encaps from beth
[01:14:25] connect ron pubkey=97f4ba3f29...2a82f2daf4
[1767658465175] INFO: awaiting encaps from ron
[01:14:25] connect ron pubkey=97f4ba3f29...2a82f2daf4
[01:14:25] connect beth pubkey=d0fa83a7be...b1f18f9fa9
list users
users:
bobbob [87fab05a438a721b73233df03cb60655319456b57241e3c481ba489ceed28099]
bethbeth [7556c04652e0e852f67cbfd2337f33d3e6c86bcb298c2040bc28a0238d53354a]
ronron [5e2da901c732f40b7b1466f573afd8b9d843cb990aab1021dac7daaa20023c58]
[01:14:53] [beth 7556c04652] hey bob
7556c04652e0e852f67cbfd2337f33d3e6c86bcb298c2040bc28a0238d53354a good day beth
[01:15:10] [beth 7556c04652] "good day beth"
[01:16:27] [ron 5e2da901c7] hello bob
5e2da901c732f40b7b1466f573afd8b9d843cb990aab1021dac7daaa20023c58 :)    
[01:16:44] [ron 5e2da901c7] ":)"
^C
$ /home/mmmm/Desktop/SPRK_dev/bin/client 127.0.0.1 1566  bob /home/mmmm/Desktop/ssh/output2.sk --sessionid yBiaFexrr7bXgTM2PB7SjjpiLdTEUQSWSxwhqAxr6GkT3KMeZcB1VskUBQhn
[1767658656873] connected
[01:17:36] connect beth pubkey=d0fa83a7be...b1f18f9fa9
[1767658656873] INFO: awaiting encaps from beth
[01:17:36] connect ron pubkey=97f4ba3f29...2a82f2daf4
[1767658656874] INFO: awaiting encaps from ron
[01:17:36] connect ron pubkey=97f4ba3f29...2a82f2daf4
[01:17:36] connect beth pubkey=d0fa83a7be...b1f18f9fa9
5e2da901c732f40b7b1466f573afd8b9d843cb990aab1021dac7daaa20023c58, back
[01:17:48] [ron 5e2da901c7] "back"
7556c04652e0e852f67cbfd2337f33d3e6c86bcb298c2040bc28a0238d53354a back
[01:18:03] [beth 7556c04652] "back"

```

### Unit ./unit.sh

```
✔ ~/Desktop/SPRK [main ↑·1|✚ 2…2] 
03:03 $ '/home/mmmm/Desktop/SPRK/unit.sh' 
=== STARTING FULL SPRK TEST SUITE ===
RUNNING: Test_001_Client_help
Test 001: Client help
SUCCESS: Help complete
RUNNING: EXEC_002_Start_server
EXEC 002: Start Server
STATUS: >>> Sending to server: 'bin/server 1566' (start server)
Connection to 127.0.0.1 1566 port [tcp/*] succeeded!
SUCCESS: Server listening
RUNNING: Test_003_Ron_connect
Test 003: Ron connects
STATUS: >>> Sending to ron: 'bin/client 127.0.0.1 1566 ron sample/sample_test_key//output.sk --sessionid nHkrMugYTkqiQzZxUDq6wzb5NMXPbRv7gBjHmaUCyLFR21onNu9KWwL3CYMK' (ron login)
DEBUG: check_output target=ron pattern=connected timeout=2 grace=3
PASS: Ron connected
DEBUG: check_output target=server pattern=connect ron session=.* timeout=2 grace=3
PASS: Server sees ron
RUNNING: Test_004_Beth_connect
Test 004: Beth connects
STATUS: >>> Sending to beth: 'bin/client 127.0.0.1 1566 beth sample/sample_test_key//output1.sk --sessionid nHkrMugYTkqiQzZxUDq6wzb5NMXPbRv7gBjHmaUCyLFR21onNu9KWwL3CYMK' (beth login)
DEBUG: check_output target=beth pattern=connected timeout=2 grace=3
PASS: Beth connected
DEBUG: check_output target=beth pattern=connect ron pubkey=.* timeout=35 grace=3
PASS: Beth sees ron
DEBUG: check_output target=beth pattern=peer ron ready timeout=35 grace=3
PASS: Beth ready with ron
DEBUG: check_output target=server pattern=connect beth session=.* timeout=2 grace=3
PASS: Server sees beth
RUNNING: Test_005_Ron_Beth_messaging_and_fp_extraction
Test 005: Ron ↔ Beth messaging + extract FPs
STATUS: Extracting FPs from ron (after Ron+Beth connected)
STATUS: >>> Sending to ron: 'list users' (extract FPs)
Updated FPs after ron list
FP_BETH_FROM_RON = 7556c04652e0e852f67cbfd2337f33d3e6c86bcb298c2040bc28a0238d53354a
FP_RON_FROM_BETH = 
FP_BOB_FROM_RON  = 
FP_BOB_FROM_BETH = 
FP_RON_FROM_BOB  = 
FP_BETH_FROM_BOB = 
STATUS: Extracting FPs from beth (from Beth's view)
STATUS: >>> Sending to beth: 'list users' (extract FPs)
Updated FPs after beth list
FP_BETH_FROM_RON = 7556c04652e0e852f67cbfd2337f33d3e6c86bcb298c2040bc28a0238d53354a
FP_RON_FROM_BETH = 5e2da901c732f40b7b1466f573afd8b9d843cb990aab1021dac7daaa20023c58
FP_BOB_FROM_RON  = 
FP_BOB_FROM_BETH = 
FP_RON_FROM_BOB  = 
FP_BETH_FROM_BOB = 
STATUS: >>> Sending to ron: '7556c04652e0e852f67cbfd2337f33d3e6c86bcb298c2040bc28a0238d53354a hello beth from ron' (ron→beth)
DEBUG: check_output target=beth pattern=\[.*\] \[ron .*] hello beth from ron timeout=2 grace=3
PASS: Beth received from ron
STATUS: >>> Sending to beth: '5e2da901c732f40b7b1466f573afd8b9d843cb990aab1021dac7daaa20023c58 hello ron from beth' (beth→ron)
DEBUG: check_output target=ron pattern=\[.*\] \[beth .*] hello ron from beth timeout=2 grace=3
PASS: Ron received from beth
RUNNING: Test_006_Bob_connect
Test 006: Bob connects + triangular rekey
STATUS: >>> Sending to bob: 'bin/client 127.0.0.1 1566 bob sample/sample_test_key//output2.sk --sessionid nHkrMugYTkqiQzZxUDq6wzb5NMXPbRv7gBjHmaUCyLFR21onNu9KWwL3CYMK' (bob login)
DEBUG: check_output target=bob pattern=connected timeout=2 grace=3
PASS: Bob connected
DEBUG: check_output target=bob pattern=connect ron pubkey=.* timeout=45 grace=3
PASS: Bob sees ron
DEBUG: check_output target=bob pattern=connect beth pubkey=.* timeout=45 grace=3
PASS: Bob sees beth
DEBUG: check_output target=bob pattern=peer ron ready timeout=45 grace=3
PASS: Bob ready with ron
DEBUG: check_output target=bob pattern=peer beth ready timeout=45 grace=3
PASS: Bob ready with beth
DEBUG: check_output target=server pattern=connect bob session=.* timeout=2 grace=3
PASS: Server sees bob
RUNNING: Test_007_Extract_all_fps_after_bob
Test 007: Extract all fingerprints after Bob joined
STATUS: Extracting FPs from ron (from Ron)
STATUS: >>> Sending to ron: 'list users' (extract FPs)
Updated FPs after ron list
FP_BETH_FROM_RON = 7556c04652e0e852f67cbfd2337f33d3e6c86bcb298c2040bc28a0238d53354a
FP_RON_FROM_BETH = 5e2da901c732f40b7b1466f573afd8b9d843cb990aab1021dac7daaa20023c58
FP_BOB_FROM_RON  = 87fab05a438a721b73233df03cb60655319456b57241e3c481ba489ceed28099
FP_BOB_FROM_BETH = 
FP_RON_FROM_BOB  = 
FP_BETH_FROM_BOB = 
STATUS: Extracting FPs from beth (from Beth)
STATUS: >>> Sending to beth: 'list users' (extract FPs)
Updated FPs after beth list
FP_BETH_FROM_RON = 7556c04652e0e852f67cbfd2337f33d3e6c86bcb298c2040bc28a0238d53354a
FP_RON_FROM_BETH = 5e2da901c732f40b7b1466f573afd8b9d843cb990aab1021dac7daaa20023c58
FP_BOB_FROM_RON  = 87fab05a438a721b73233df03cb60655319456b57241e3c481ba489ceed28099
FP_BOB_FROM_BETH = 87fab05a438a721b73233df03cb60655319456b57241e3c481ba489ceed28099
FP_RON_FROM_BOB  = 
FP_BETH_FROM_BOB = 
STATUS: Extracting FPs from bob (from Bob)
STATUS: >>> Sending to bob: 'list users' (extract FPs)
Updated FPs after bob list
FP_BETH_FROM_RON = 7556c04652e0e852f67cbfd2337f33d3e6c86bcb298c2040bc28a0238d53354a
FP_RON_FROM_BETH = 5e2da901c732f40b7b1466f573afd8b9d843cb990aab1021dac7daaa20023c58
FP_BOB_FROM_RON  = 87fab05a438a721b73233df03cb60655319456b57241e3c481ba489ceed28099
FP_BOB_FROM_BETH = 87fab05a438a721b73233df03cb60655319456b57241e3c481ba489ceed28099
FP_RON_FROM_BOB  = 5e2da901c732f40b7b1466f573afd8b9d843cb990aab1021dac7daaa20023c58
FP_BETH_FROM_BOB = 7556c04652e0e852f67cbfd2337f33d3e6c86bcb298c2040bc28a0238d53354a
RUNNING: Test_008_Triangular_messaging
Test 008: Full triangular messaging
STATUS: >>> Sending to ron: '87fab05a438a721b73233df03cb60655319456b57241e3c481ba489ceed28099 hi bob from ron' (ron→bob)
DEBUG: check_output target=bob pattern=\[.*\] \[ron .*] hi bob from ron timeout=2 grace=3
PASS: Bob got from ron
STATUS: >>> Sending to beth: '87fab05a438a721b73233df03cb60655319456b57241e3c481ba489ceed28099 hi bob from beth' (beth→bob)
DEBUG: check_output target=bob pattern=\[.*\] \[beth .*] hi bob from beth timeout=2 grace=3
PASS: Bob got from beth
STATUS: >>> Sending to bob: '5e2da901c732f40b7b1466f573afd8b9d843cb990aab1021dac7daaa20023c58 hi ron from bob' (bob→ron)
DEBUG: check_output target=ron pattern=\[.*\] \[bob .*] hi ron from bob timeout=2 grace=3
PASS: Ron got from bob
STATUS: >>> Sending to bob: '7556c04652e0e852f67cbfd2337f33d3e6c86bcb298c2040bc28a0238d53354a hi beth from bob' (bob→beth)
DEBUG: check_output target=beth pattern=\[.*\] \[bob .*] hi beth from bob timeout=2 grace=3
PASS: Beth got from bob
RUNNING: Test_009_Multi_recipient
Test 009: Multi-recipient messaging
STATUS: >>> Sending to ron: '7556c04652e0e852f67cbfd2337f33d3e6c86bcb298c2040bc28a0238d53354a,87fab05a438a721b73233df03cb60655319456b57241e3c481ba489ceed28099 group hello from ron' (group)
DEBUG: check_output target=beth pattern=\[.*\] \[ron .*] group hello from ron timeout=2 grace=3
PASS: Beth got group
DEBUG: check_output target=bob pattern=\[.*\] \[ron .*] group hello from ron timeout=2 grace=3
PASS: Bob got group
RUNNING: Test_010_Client_commands
Test 010: Client commands
STATUS: >>> Sending to ron: 'pubk beth' (pubk beth)
DEBUG: check_output target=ron pattern=pubkey beth timeout=5 grace=3
PASS: Ron fetched beth pubkey
STATUS: >>> Sending to ron: 'pubk bob' (pubk bob)
DEBUG: check_output target=ron pattern=pubkey bob timeout=5 grace=3
PASS: Ron fetched bob pubkey
STATUS: >>> Sending to beth: 'pubk ron' (pubk ron)
DEBUG: check_output target=beth pattern=pubkey ron timeout=5 grace=3
PASS: Beth fetched ron pubkey
STATUS: >>> Sending to beth: 'pubk bob' (pubk bob)
DEBUG: check_output target=beth pattern=pubkey bob timeout=5 grace=3
PASS: Beth fetched bob pubkey
STATUS: >>> Sending to bob: 'pubk ron' (pubk ron)
DEBUG: check_output target=bob pattern=pubkey ron timeout=5 grace=3
PASS: Bob fetched ron pubkey
STATUS: >>> Sending to bob: 'pubk beth' (pubk beth)
DEBUG: check_output target=bob pattern=pubkey beth timeout=5 grace=3
PASS: Bob fetched beth pubkey
RUNNING: Test_011_Post_Ron_reconnect_full_verification
Test 011: Full verification after Ron reconnect
STATUS: >>> Sending to ron: 'q' (quit ron)
STATUS: >>> Sending to ron: 'bin/client 127.0.0.1 1566 ron sample/sample_test_key//output.sk --sessionid nHkrMugYTkqiQzZxUDq6wzb5NMXPbRv7gBjHmaUCyLFR21onNu9KWwL3CYMK' (ron relogin)
DEBUG: check_output target=ron pattern=connected timeout=2 grace=3
PASS: Ron reconnected
DEBUG: check_output target=ron pattern=peer beth ready timeout=45 grace=3
PASS: Ron ready with beth (post-reconnect)
DEBUG: check_output target=ron pattern=peer bob ready timeout=45 grace=3
PASS: Ron ready with bob (post-reconnect)
STATUS: Extracting FPs from ron (post-reconnect)
STATUS: >>> Sending to ron: 'list users' (extract FPs)
Updated FPs after ron list
FP_BETH_FROM_RON = 7556c04652e0e852f67cbfd2337f33d3e6c86bcb298c2040bc28a0238d53354a
FP_RON_FROM_BETH = 5e2da901c732f40b7b1466f573afd8b9d843cb990aab1021dac7daaa20023c58
FP_BOB_FROM_RON  = 87fab05a438a721b73233df03cb60655319456b57241e3c481ba489ceed28099
FP_BOB_FROM_BETH = 87fab05a438a721b73233df03cb60655319456b57241e3c481ba489ceed28099
FP_RON_FROM_BOB  = 5e2da901c732f40b7b1466f573afd8b9d843cb990aab1021dac7daaa20023c58
FP_BETH_FROM_BOB = 7556c04652e0e852f67cbfd2337f33d3e6c86bcb298c2040bc28a0238d53354a
STATUS: >>> Sending to ron: '87fab05a438a721b73233df03cb60655319456b57241e3c481ba489ceed28099 post-reconnect hi bob from ron' (post-reconnect ron→bob)
DEBUG: check_output target=bob pattern=\[.*\] \[ron .*] post-reconnect hi bob from ron timeout=2 grace=3
PASS: Bob got post-reconnect
STATUS: >>> Sending to beth: '87fab05a438a721b73233df03cb60655319456b57241e3c481ba489ceed28099 post-reconnect hi bob from beth' (post-reconnect beth→bob)
DEBUG: check_output target=bob pattern=\[.*\] \[beth .*] post-reconnect hi bob from beth timeout=2 grace=3
PASS: Bob got post-reconnect from beth
STATUS: >>> Sending to bob: '5e2da901c732f40b7b1466f573afd8b9d843cb990aab1021dac7daaa20023c58 post-reconnect hi ron from bob' (post-reconnect bob→ron)
DEBUG: check_output target=ron pattern=\[.*\] \[bob .*] post-reconnect hi ron from bob timeout=2 grace=3
PASS: Ron got post-reconnect from bob
STATUS: >>> Sending to ron: 'list users' (post-reconnect list)
DEBUG: check_output target=ron pattern=beth.*\[.*\] timeout=2 grace=3
PASS: List shows beth (post-reconnect)
DEBUG: check_output target=ron pattern=bob.*\[.*\] timeout=2 grace=3
PASS: List shows bob (post-reconnect)

════════════════════════════════════════════════════════
                ALL TESTS COMPLETED - PASS            
  ════════════════════════════════════════════════════════
   ✓ Ron connected
   ✓ Server sees ron
   ✓ Beth connected
   ✓ Beth sees ron
   ✓ Beth ready with ron
   ✓ Server sees beth
   ✓ Beth received from ron
   ✓ Ron received from beth
   ✓ Bob connected
   ✓ Bob sees ron
   ✓ Bob sees beth
   ✓ Bob ready with ron
   ✓ Bob ready with beth
   ✓ Server sees bob
   ✓ Bob got from ron
   ✓ Bob got from beth
   ✓ Ron got from bob
   ✓ Beth got from bob
   ✓ Beth got group
   ✓ Bob got group
   ✓ Ron fetched beth pubkey
   ✓ Ron fetched bob pubkey
   ✓ Beth fetched ron pubkey
   ✓ Beth fetched bob pubkey
   ✓ Bob fetched ron pubkey
   ✓ Bob fetched beth pubkey
   ✓ Ron reconnected
   ✓ Ron ready with beth (post-reconnect)
   ✓ Ron ready with bob (post-reconnect)
   ✓ Bob got post-reconnect
   ✓ Bob got post-reconnect from beth
   ✓ Ron got post-reconnect from bob
   ✓ List shows beth (post-reconnect)
   ✓ List shows bob (post-reconnect)

═══════════════════════════════════════════════════════════════════════════
Total successful checks: 34
═══════════════════════════════════════════════════════════════════════════
=== CLEANUP STARTED ===
=== CLEANUP DONE ===
✔ ~/Desktop/SPRK [main ↑·1|✚ 2…2] 
 

```
