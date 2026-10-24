# Compliance Circuit — Audit Notes

> 2026-07-09, self-review pass (fable oturumu, salt okuma — kod DEĞİŞTİRİLMEDİ).
> Amaç: hem güvenlik gözden geçirme hem "kalem-kağıt anlatım" için ZK yüzeyini netleştirmek.
> `compliance.circom` (N=8, levels=8, nBits=64) + `contracts/compliance_verifier/src/lib.rs`.

## Doğru yapılmış (koruyalım — regresyon olmasın)

- **Range-check-before-compare** (`compliance.circom:82-87`): `Num2Bits(64)` amount'u karşılaştırmadan önce bit'e hapsediyor → field mod-p negatif-wrap ile limit atlatma kapalı. ZK'nın en klasik soundness tuzağı; kapatılmış.
- **CSPRNG salt** (`prove.ts:42`, `packages/prover/src/salt.ts`): commitment `Poseidon(amount,payee,salt)` gerçekten gizliyor; salt zayıf olsa küçük miktar uzayında brute-force ile açılırdı.
- **On-chain replay guard** (`lib.rs:166-174`): `periodId` persistent storage'da bir kez tüketiliyor. periodId devrede constraint'siz ("public binding only") ama Groth16 public-input commitment'ı sayesinde yine de güvenli — proof başka periodId'ye taşınamaz.
- **Policy binding** (`lib.rs:153-164`): proof'un limitleri kontratın deploy'da çıpaladığı politikayla eşleşmezse `panic`. Bu olmasa verifier "agent kendi seçtiği politikaya uydu" diyen vacuous oracle olurdu.
- **Atomic constructor** (`lib.rs:101`): front-run edilebilir `initialize` yok; policy + admin deploy anında çıpalı.
- **Padding güvenli** (`prove.ts:33,39-40`): boş slot amount=0, payee=whitelist[0] → merkle + commitment tutarlı, dummy leak yok.

## AÇIK — sonraki oturumda değerlendir

### 1. (MİMARİ, en önemli) commitment ↔ gerçek treasury hareketi bağı
Devre "uyumlu bir batch VAR"ı kanıtlıyor; commitment'ların treasury'nin GERÇEKTEN yaptığı ödemeler olduğunu devre/verifier tek başına garanti etmiyor. Bu bağ kurulmazsa agent uyumlu ama HAYALİ bir batch kanıtlayıp gerçekte başka türlü harcayabilir.
- `treasury/lib.rs:419-420` "session cap charges at commitment time" → bir bağ VAR GİBİ ama izi tam sürülmedi.
- **Yapılacak:** treasury'nin escrow/commitment akışı ile verifier'ın tükettiği `commitments[8]` aynı commitment'lar mı? Aynıysa sistem sağlam (ve bu en güçlü savunma kozu). Değilse köprü eksik = gerçek açık.
- Bu, ZK sistemlerinin en sık kırıldığı yer: devrenin İÇİ değil, devre ↔ gerçek-dünya köprüsü.

### 2. (DÜŞÜK RİSK, gerçek) public limitler range-check edilmiyor
`perTaskLimit` / `dailyLimit` ne devrede ne `__constructor`'da bound'lanıyor. "Owner-trusted" ile güvenli AMA owner yanlışlıkla `>= 2^64` bir limit çıpalarsa `LessEqThan` sessizce bozulabilir.
- **Fix (tek satır):** `__constructor`'da `daily_limit < 2^64 && per_task_limit < 2^64` assert. Temiz bir hardening commit'i.

### 3. (GELECEK-TUZAĞI, şu an güvenli) N=16 yorumu vs bit genişliği
`compliance.circom:103` yorumu "N<=16 => total < 2^(nBits+4)" diyor ama 16*2^64 = 2^68, `nBits+4=68` bit'e TAM sığmaz (bir bit eksik). N=8'de güvenli (8*2^64=2^67<2^68). N artırılırsa `Num2Bits(nBits+5)` + `LessEqThan(nBits+5)` gerekir.

## Avalanche portu için not
Aynı üçlü (Circom devre + Groth16 + verifier), tek fark verifier'ın Solidity/C-Chain'de olması (EVM'de BN254 precompile'ları hazır). Bulgu 1 (commitment↔state köprüsü) Avalanche ürününde `BoundedAgentAccount` tasarımının merkezi sorusu → bkz Team1 grant ADR.

---

## ÇAPRAZ-KONTROL (2026-07-09, Stellar oturumu — bulgular koda karşı doğrulandı)

### Bulgu 1 — DOĞRULANDI, iz sürüldü: köprü bugün YOK (ipucu çıkmaz sokakmış)
`treasury/lib.rs:419-420`'deki "session cap charges at **commitment** time" yorumu `create_escrow` içinde — oradaki "commitment" **escrow'a fon kilitleme** demek, ZK Poseidon commitment'larıyla kelime çakışması. Treasury hiçbir yerde Poseidon commitment görmüyor/saklamıyor/yayınlamıyor; `pay()` düz-metin `(paid, task_id) → (to, amount)` event'i basıyor, batch input'u prover kendi JSON'ından kuruyor (`prove.ts` buildInput). **Sonuç:** attestation'ın bugünkü dürüst tanımı = "beyan edilen batch, çıpalı politikaya uyuyor" — "treasury'nin zincirdeki GERÇEK harcamaları buydu" DEĞİL (zaten reference-attestation diye etiketliyoruz). Fon güvenliği açığı değil (fonlar kontratla sınırlı); attestation'ın kanıt gücünün sınırı. **Çözüm yönü:** pay anında commitment accumulator — kontrat her ödemede `Poseidon(amount,payee,salt)`'ı saklar/event'ler, verifier batch'i o birikmiş set'e karşı doğrular → attestation gerçek akışı kanıtlar. (Tam gizli transfer istenirse OZ confidential-token hattı; ayrı, büyük iş.)

### Bulgu 2 — ✅ KAPANDI (hardening v2, commit `d6f315e`)
Devrede `perTaskLimit` karşılaştırması `LessEqThan(nBits)` (=64 bit), `dailyLimit` karşılaştırması `LessEqThan(nBits+4)` (=68 bit). `__constructor`'a `fits_bits` assert'i eklendi (`per_task < 2^64 && daily < 2^68`), 3 yeni test, 7/7 yeşil. **Redeploy notu:** canlı verifier'ın çıpalı politikası zaten aralıkta → davranışı değişmez; adres churn'ü yaşamamak için redeploy accumulator deploy'una katlanacak (o zaten yeni verifier ister).

### Bulgu 3 — FALSE ALARM, yorum gerekçelendirildi ✅ (commit `cb7836e`)
`Num2Bits(64)` amount'u `≤ 2^64-1`'e hapseder (2^64 değil). N=16'da maksimum toplam = `16·(2^64-1) = 2^68-16 < 2^68` → `Num2Bits(68)`'e **sığar**, yorumdaki "N<=16" doğru. Marj 16 birim — devre yorumuna tam hesap + "N>16 ⇒ nBits+5" kuralı yazıldı (constraint değişikliği yok).

### Bulgu 4 — Merkle empty-leaf padding (`0n` vs `H(0)`) ✅
`helpers.ts` boş yaprakları `H([0n])` (`Poseidon(0)`) ile dolduruyordu; devre her payee'yi `Poseidon(payee)` olarak yaprakladığı için `< 256` üyeli her ağaçta `payee = 0` üyelik kontrolünden geçiyordu. Boş yapraklar artık hiçbir `Poseidon(x)` çıktısı olamayan literal `0n` ile dolduruluyor (yalnızca off-chain, yeni trusted setup gerekmez). **Not:** Önceki `H(0)` dolgusuyla `whitelist_root` yayınlamış kasa sahiplerinin `whitelist_root` değerini yeniden yayınlaması (`set_whitelist_root` / `--publish-root`) gerekir.

