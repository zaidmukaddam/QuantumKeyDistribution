import streamlit as st
import hashlib
import json
from qiskit import QuantumCircuit, QuantumRegister, transpile
from qiskit_aer import QasmSimulator

# Quantum Key Generation
def generate_quantum_key(qubits):
    qr = QuantumRegister(qubits)
    qc = QuantumCircuit(qr)

    # Apply Hadamard gates to all qubits
    for i in range(qubits):
        qc.h(qr[i])

    qc.measure_all()

    # Perform quantum computation
    simulator = QasmSimulator()
    compiled_circuit = transpile(qc, simulator)
    result = simulator.run(compiled_circuit, shots=1).result()

    # Convert qubit states to a classical key
    key = list(result.get_counts())[0]
    return key


# Quantum Key Distribution
def distribute_quantum_key(sender_key, receiver_key):
    shared_key = ''

    # Create a shared key by XORing the sender's and receiver's keys
    for s_bit, r_bit in zip(sender_key, receiver_key):
        shared_key += str(int(s_bit) ^ int(r_bit))

    return shared_key

# Quantum Key Management
class QuantumKeyManager:
    def __init__(self, qubits):
        self.qubits = qubits

    def generate_key_pair(self):
        sender_key = generate_quantum_key(self.qubits)
        receiver_key = generate_quantum_key(self.qubits)
        return sender_key, receiver_key

    def create_shared_key(self, sender_key, receiver_key):
        return distribute_quantum_key(sender_key, receiver_key)

# API Security
class QuantumApiSecurity:
    def __init__(self, shared_key):
        self.shared_key = shared_key

    def sign_request(self, payload):
        m = hashlib.sha256()
        m.update(self.shared_key.encode())
        m.update(json.dumps(payload).encode())
        signature = m.hexdigest()
        return signature

    def authenticate_request(self, payload, signature):
        calculated_signature = self.sign_request(payload)
        return calculated_signature == signature


def main():
    st.set_page_config(page_title="Quantum Key Manager", layout="wide")
    st.title("Quantum Key Manager")

    qubits = st.sidebar.slider(
        "Select number of qubits", min_value=8, max_value=256, value=8, step=8)
    qkm = QuantumKeyManager(qubits)

    if st.button("Generate Quantum Key Pair"):
        sender_key, receiver_key = qkm.generate_key_pair()
        shared_key = qkm.create_shared_key(sender_key, receiver_key)

        st.write(f"Sender key: {sender_key}")
        st.write(f"Receiver key: {receiver_key}")
        st.write(f"Shared key: {shared_key}")

        api_security = QuantumApiSecurity(shared_key)
        st.session_state["api_security"] = api_security

    if "api_security" in st.session_state:
        st.subheader("API Request Signing & Verification")

        payload_str = st.text_area("Enter API request payload as JSON", '{"command": "deploy", "project_id": "12345", "commit_hash": "a3c7d934f2e9"}')
        payload = json.loads(payload_str)

        if st.button("Sign API Request"):
            signature = st.session_state["api_security"].sign_request(payload)
            st.write(f"Signature: {signature}")

            # Add an input field for the signature
            input_signature = st.text_input("Enter the signature to verify")

            if st.button("Verify API Request Signature"):
                if not input_signature:
                    st.warning("Please enter a signature to verify.")
                else:
                    authenticated = st.session_state["api_security"].authenticate_request(payload, signature)

                    if authenticated:
                        st.success("Request authenticated successfully.")
                    else:
                        st.error("Request authentication failed.")

if __name__ == "__main__":
    main()
