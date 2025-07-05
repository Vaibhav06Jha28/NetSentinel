import pickle
import numpy as np

model = pickle.load(open('ml_model/netsentinel_model.pkl', 'rb'))

def is_anomalous(packet):
    # Feature: [packet_length]
    features = np.array([[packet['length']]])
    return bool(model.predict(features)[0])
