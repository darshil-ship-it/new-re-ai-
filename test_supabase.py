from supabase import create_client
from dotenv import load_dotenv
import os

load_dotenv()

try:
    supabase = create_client(
        os.getenv('SUPABASE_URL'),
        os.getenv('SUPABASE_ANON_KEY')
    )
    
    print("✅ Supabase client created successfully!")
    print(f"URL: {os.getenv('SUPABASE_URL')}")
    
    # Try to send OTP
    email = "test@example.com"  # Use your real email
    result = supabase.auth.sign_in_with_otp({'email': email})
    print("✅ OTP sent successfully!")
    print(result)
    
except Exception as e:
    print(f"❌ Error: {e}")
    print(f"Error type: {type(e)}")