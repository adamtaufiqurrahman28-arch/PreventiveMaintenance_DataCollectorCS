# Changelog

## 15.0.6.2

- Memperbaiki parser payload Prevention Policy resmi yang berbentuk section container `name + settings[]`.
- Nilai configuration item sekarang diambil dari setiap `settings[].value`, sehingga ON/OFF dan level detection/prevention tampil pada matrix GUI dan Excel.
- Nama item dan section menggunakan label resmi dari API ketika tidak ada mapping override.
- Item yang tidak tersedia pada sebuah policy ditampilkan sebagai `N/A`, bukan sel kosong.
- Tetap mempertahankan perbaikan duplicate policy name untuk Pandas Styler/Streamlit.
- Menambahkan regression test untuk nested Prevention Policy payload.

## 15.0.6

- Fixed Prevention Policy matrix showing structural fields as rows.
- Added official-style `settings[].id/value` parser.
- Added compound value normalization for detection/prevention levels.
- Added built-in configuration item label mapping.
- Added editable mapping table in Streamlit GUI.
- Added rebuild-from-last-API-data action.
- Added platform matrix preview in GUI.
- Added Summary, Policy Groups, Disabled Items, Non-Compliant Items, All Settings, Unmapped Items, Raw Policy API, and Query Information sheets.
- Added section grouping and improved matrix formatting.
- Added tests confirming Type/Value/Detection/Prevention are not emitted as configuration items.

## 15.0.5

- Combined Host Detail and Sensor Health into Lampiran A.
- Added editable Sensor Matrix in GUI.
- Integrated standalone detection exporter.
