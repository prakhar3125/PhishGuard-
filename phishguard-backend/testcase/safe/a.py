import os

# Safe rename script
# Run this inside the folder containing the raw email files
count = 0
for filename in os.listdir("."):
    if os.path.isfile(filename) and not filename.endswith(".py") and not filename.endswith(".eml"):
        try:
            new_name = f"{filename}.eml"
            os.rename(filename, new_name)
            count += 1
        except Exception as e:
            print(f"Skipped {filename}: {e}")

print(f"✅ Renamed {count} files to .eml format")