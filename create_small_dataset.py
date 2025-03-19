import pandas as pd

# Load the original dataset
df = pd.read_csv('malicious_phish.csv')

# Create a smaller sample (10% of original data)
small_df = df.sample(frac=0.1, random_state=42)

# Save the smaller dataset
small_df.to_csv('malicious_phish_small.csv', index=False)

print(f"Created small dataset with {len(small_df)} samples") 