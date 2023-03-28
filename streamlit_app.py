import streamlit as st
from quantum_key_management import QuantumKeyManager, QuantumApiSecurity

st.set_page_config(page_title="Quantum Key Management App", layout="wide")

st.title("Advanced Quantum Key Management for API Security")

qubits = st.sidebar.slider("Select number of qubits", 4, 256, 16)
qkm = QuantumKeyManager(qubits)

with st.expander("Generate Quantum Key Pair"):
    sender_key, receiver_key = qkm.generate_key_pair()
    st.write(f"Sender Key: {sender_key}")
    st.write(f"Receiver Key: {receiver_key}")

with st.expander("Create Shared Key"):
    shared_key = qkm.create_shared_key(sender_key, receiver_key)
    st.write(f"Shared Key: {shared_key}")

api_security = QuantumApiSecurity(shared_key)

with st.expander("Sign and Authenticate API Request"):
    payload = {
        "command": "deploy",
        "project_id": "12345",
        "commit_hash": "a3c7d934f2e9",
    }
    st.write("API Request Payload:")
    st.json(payload)

    signature = api_security.sign_request(payload)
    st.write(f"Generated Signature: {signature}")

    if api_security.authenticate_request(payload, signature):
        st.success("Request authenticated successfully.")
    else:
        st.error("Request authentication failed.")
