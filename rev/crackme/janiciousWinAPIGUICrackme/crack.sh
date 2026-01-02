#!/bin/bash

HEX="69470c4d523504d8c842eb93"
ZIP="69470c4d523504d8c842eb93.zip"

echo "Testing ALL possibilities for: $HEX"

# 1. The hex itself
echo "1. Hex as password: $HEX"
unzip -P "$HEX" "$ZIP" 2>/dev/null && echo "   ✅ SUCCESS!" && exit 0

# 2. Convert hex to ASCII (might be readable text)
echo -n "2. Hex to ASCII: "
ASCII=$(echo "$HEX" | xxd -r -p)
echo "'$ASCII'"
unzip -P "$ASCII" "$ZIP" 2>/dev/null && echo "   ✅ SUCCESS!" && exit 0

# 3. Try base64 of the hex
echo -n "3. Base64 of hex: "
B64=$(echo "$HEX" | xxd -r -p | base64)
echo "'$B64'"
unzip -P "$B64" "$ZIP" 2>/dev/null && echo "   ✅ SUCCESS!" && exit 0

# 4. Try reversing
echo "4. Reversed hex: $(echo $HEX | rev)"
unzip -P "$(echo $HEX | rev)" "$ZIP" 2>/dev/null && echo "   ✅ SUCCESS!" && exit 0

# 5. Try pairs reversed (common in crypto)
echo -n "5. Byte-swapped (little-endian): "
SWAPPED=$(echo $HEX | sed 's/\(..\)\(..\)/\2\1/g')
echo "$SWAPPED"
unzip -P "$SWAPPED" "$ZIP" 2>/dev/null && echo "   ✅ SUCCESS!" && exit 0

# 6. Try without last/first chars
echo "6. Without last char: ${HEX:0:23}"
unzip -P "${HEX:0:23}" "$ZIP" 2>/dev/null && echo "   ✅ SUCCESS!" && exit 0

echo "7. Without first char: ${HEX:1}"
unzip -P "${HEX:1}" "$ZIP" 2>/dev/null && echo "   ✅ SUCCESS!" && exit 0

# 7. Common CTF variations
echo "8. Trying 'infected', 'virus', 'malware'..."
for p in infected virus malware crackme winapi password 123456; do
    unzip -P "$p" "$ZIP" 2>/dev/null && echo "   ✅ SUCCESS with: $p" && exit 0
done

echo "❌ Need dictionary attack..."
