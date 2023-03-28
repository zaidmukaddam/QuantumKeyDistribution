import numpy as np
import streamlit as st
import hashlib
import json
from qiskit import ClassicalRegister, QuantumCircuit, QuantumRegister, transpile
from qiskit_aer import QasmSimulator


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
        qr = QuantumRegister(self.qubits)
        cr = ClassicalRegister(self.qubits)
        qc_sender = QuantumCircuit(qr, cr)
        qc_receiver = QuantumCircuit(qr, cr)

        def encode_and_measure(qc, bits):
            for i, bit in enumerate(bits):
                if bit == 0:
                    qc.h(qr[i])  # encode 0 as |+>
                else:
                    qc.x(qr[i])
                    qc.h(qr[i])  # encode 1 as |->
                # Measure in rectilinear basis (Z-basis)
                qc.measure(qr[i], cr[i])

        # Generate random bits for encoding
        bits_sender = np.random.randint(2, size=self.qubits)
        # Encode bits using BB84 protocol
        encode_and_measure(qc_sender, bits_sender)

        # Perform quantum computation
        simulator = QasmSimulator()
        compiled_circuit = transpile(qc_sender, simulator)
        result = simulator.run(compiled_circuit, shots=1).result()

        # Decode key using rectilinear basis (Z-basis)
        sender_key = ""
        for i in range(self.qubits):
            if bits_sender[i] == 0:
                sender_key += str(int(list(result.get_counts())[0][i]))  # measure in rectilinear basis (Z-basis)
            else:
                sender_key += str(int(not int(list(result.get_counts())[0][i])))  # measure in rectilinear basis (Z-basis)

        # Generate new random bits for encoding
        bits_receiver = np.random.randint(2, size=self.qubits)
        # Encode bits using BB84 protocol
        encode_and_measure(qc_receiver, bits_receiver)

        # Perform quantum computation
        compiled_circuit = transpile(qc_receiver, simulator)
        result = simulator.run(compiled_circuit, shots=1).result()

        # Decode key using rectilinear basis (Z-basis)
        receiver_key = ""
        for i in range(self.qubits):
            if bits_receiver[i] == 0:
                receiver_key += str(int(list(result.get_counts())[0][i]))  # measure in rectilinear basis (Z-basis)
            else:
                receiver_key += str(int(not int(list(result.get_counts())[0][i])))  # measure in rectilinear basis (Z-basis)

        return sender_key, receiver_key

    # Create shared key by XORing the sender's and receiver's keys
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
            api_security = st.session_state["api_security"]
            signature = api_security.sign_request(payload)
            st.write(f"Signature: {signature}")
            st.session_state["signature"] = signature

        input_signature = st.text_input("Enter the signature to be verified")
        if st.button("Verify API Request Signature"):
            api_security = st.session_state["api_security"]
            if input_signature == "":
                st.warning("Please input a signature to be verified.")
            else:
                authenticated = api_security.authenticate_request(payload, input_signature)

                if authenticated:
                    st.success("Request authenticated successfully.",icon="✅")
                else:
                    st.error("Request authentication failed.",icon="❌")



if __name__ == "__main__":
    main()
