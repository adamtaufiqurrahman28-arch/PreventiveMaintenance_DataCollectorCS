# Release Notes — v15.0.6.2

V15.0.6.2 memperbaiki akar masalah matrix Prevention Policy yang hanya menampilkan nama item tetapi seluruh nilai policy kosong. CrowdStrike mengembalikan data dalam section container seperti `{"name": "Enhanced Visibility", "settings": [...]}`. Versi sebelumnya salah menganggap section tersebut sebagai satu configuration item.

Perbaikan:

- Parser sekarang masuk ke setiap `settings[]` dan membaca `id`, `name`, `type`, serta `value`.
- Toggle ditampilkan sebagai `ON` atau `OFF`.
- Machine-learning slider ditampilkan sebagai nilai detection/prevention.
- Nama item dan section resmi dari API dipakai ketika tidak ada mapping override.
- Setting yang memang tidak tersedia pada suatu policy ditampilkan sebagai `N/A`.
- Duplicate policy names tetap aman untuk Pandas Styler/Streamlit.
- Regression test ditambahkan untuk struktur payload tenant nyata.

# Release Notes — v15.0.6

## Prevention Policy normalizer

- Memproses struktur resmi `settings[].id` dan `settings[].value`.
- Menggabungkan helper field `type`, `value`, `detection`, dan `prevention` menjadi satu configuration record.
- Mencegah baris palsu bernama Type, Value, Detection, atau Prevention.
- Mendukung payload lama berbentuk nested dictionary.
- Menyimpan raw value, value type, detection level, dan prevention level untuk audit.

## GUI

- Configuration Item Label Mapping editable langsung di Streamlit.
- Rebuild matrix dari hasil API terakhir tanpa pull ulang.
- Preview matrix Windows, Linux, dan Mac.
- Preview Disabled Items, Not Compliant, All Settings, dan Unmapped Items.

## Excel Prevention Policy

- Matrix satu baris per configuration item.
- Section separator agar matrix tidak berantakan.
- Maksimal 14 policy per matrix sheet.
- Sheet Disabled Items untuk daftar item OFF per policy.
- Sheet Non-Compliant Items untuk hasil baseline assessment.
- Sheet All Settings dan Raw Policy API untuk audit.

## Compatibility

- Host/Sensor Health tidak diubah.
- Detection standalone flow tidak diubah.
- Sensor Matrix tetap editable di GUI.
