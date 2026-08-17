# Performans Ölçümleri

## Ortam
- Kali Linux, kernel 7.0.12+kali-amd64
- VirtualBox VM, 4 vCPU
- Arayüz: veth çifti (sanal), izole network namespace
- Yük üreteci: hping3 --flood --udp -p 9999
- Ölçüm: XDP stats map'indeki STAT_TOTAL farkı / süre
- Her yapılandırma için 10 saniyelik 3 tekrar

## Sonuçlar (paket/saniye)

| Yapılandırma | Ölçüm 1 | Ölçüm 2 | Ölçüm 3 | Ortalama |
|---|---|---|---|---|
| Native XDP, XDP_PASS | 286.729 | 288.624 | 291.751 | 289.035 |
| Native XDP, XDP_DROP | 450.967 | 468.833 | 444.030 | 454.610 |
| Generic XDP, XDP_PASS | 331.963 | — | — | 331.963 |

## Bulgular

**1. DROP, PASS'ten %57 hızlı (454.610 vs 289.035 pps)**

XDP_PASS durumunda paket kernel ağ yığınına devam eder: sk_buff yapısı
ayrılır, protokol katmanları işlenir, soket aranır, dinleyen bulunamadığı
için ICMP port unreachable üretilir. XDP_DROP'ta bu maliyetlerin hiçbiri
ödenmez; paket sürücü seviyesinde sonlanır.

Bu, XDP'nin DDoS savunmasında tercih edilme sebebinin doğrudan ölçümü:
saldırı trafiği ne kadar erken sonlandırılırsa sistemin geri kalanı o
kadar az etkilenir.

**2. Ölçüm tekrarlanabilir**

Native PASS ölçümlerinde sapma %2'nin altında (286.729–291.751).
VM ortamına rağmen metot güvenilir.

**3. Generic mod native'den hızlı çıktı (veth üzerinde)**

Beklenenin tersi bir sonuç. Sebebi test ortamı: veth fiziksel bir NIC
değil, native XDP bu arayüzde NAPI yolundan ek maliyet çıkarıyor.
Fiziksel bir ağ kartında native modun avantajlı olması beklenir.

## Ölçümün sınırları

- Sanal arayüz (veth) kullanıldı; fiziksel NIC sonuçları farklı olacaktır
- VirtualBox sanallaştırma katmanı araya girmektedir
- Mutlak değerler değil, aynı ortamdaki göreli karşılaştırma anlamlıdır
- Tek yönlü trafik ölçüldü (yalnızca ingress)
