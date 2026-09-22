cd ~/Work/Defi/Defi_analysis

echo "=== TONG SO FILE JSON THUC TE ==="
find data/features_graph -name "*_static.json" | wc -l

echo ""
echo "=== PHAN BO LABEL (1=vulnerable, 0=safe) ==="
find data/features_graph -name "*_static.json" -exec grep -h '"label"' {} \; \
    | grep -oE '"label": *[01]' \
    | sort | uniq -c
