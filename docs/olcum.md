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

---

# Karşılaştırmalı Ölçüm (Gün 16)

## Yöntem

Aynı UDP paket seli (hping3 --flood, port 9999) dört farklı yapılandırmada
çalıştırıldı. Metrik: /proc/stat'tan okunan system+irq+softirq jiffy
değerinin milyon paket başına düşen miktarı. Düşük değer = paket başına
daha az CPU = daha verimli.

Her yapılandırma 10 saniye, 3 tekrar.

## Sonuçlar (jiffy / milyon paket)

| Yapılandırma | Tur 1 | Tur 2 | Tur 3 | Ortalama |
|---|---|---|---|---|
| 1. Filtresiz (kernel'e kadar) | 243 | 250 | 258 | 250 |
| 2. iptables DROP | 200 | 178 | 202 | 193 |
| 3. nftables drop | 177 | 193 | 179 | 183 |
| 4. XDP DROP | 155 | 187 | 162 | 168 |

## Bulgular

**1. Filtreleme yapmamak en pahalısı (%33 fark)**

Filtresiz durumda paket UDP soket tablosuna kadar ilerler, dinleyen
bulunamadığı için ICMP port unreachable üretilir. XDP'de paket sürücü
seviyesinde sonlandığı için bu maliyetlerin hiçbiri ödenmez.

**2. Sıralama tutarlı: XDP < nftables < iptables < filtresiz**

Üç tekrarın hepsinde aynı sıralama gözlendi. Bu, paketin ne kadar erken
sonlandırıldığıyla doğrudan orantılı: XDP sürücü seviyesinde, netfilter
tabanlı çözümler ise sk_buff yapısı oluşturulduktan sonra devreye girer.

**3. Farkların büyüklüğü bu ortamda ölçülemez**

Filtreleme yaklaşımları arasındaki fark %13 civarında, ancak tur içi sapma
%10'a ulaşıyor. Sıralama anlamlı, oranlar değil.

## Ölçümün sınırları

- veth sanal arayüz kullanıldı; fiziksel NIC'te farklar belirginleşir
- Yük üreteci (hping3) ile alıcı aynı 4 çekirdekli VM'de çalışıyor;
  CPU maliyetinin ne kadarının gönderici tarafa ait olduğu ayrıştırılamıyor
- VirtualBox sanallaştırma katmanı araya girmektedir
- Sağlıklı bir karşılaştırma için ayrı fiziksel makineler ve gerçek NIC gerekir

Bu kısıtlar nedeniyle "XDP iptables'tan N kat hızlıdır" gibi bir iddia
bu ölçümlerle desteklenemez. Güvenilir olan bulgu, Gün 11'de aynı program
içinde ölçülen XDP_DROP vs XDP_PASS farkıdır (%57, sapma <%2).
