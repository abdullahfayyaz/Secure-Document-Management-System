import PyPDF2
import joblib

# Load the trained model
model = joblib.load('SecureDocAI/static/model/news_classifier.pkl')


def classify_pdf_(file_path):
    # Extract text from PDF
    with open(file_path, 'rb') as file:
        reader = PyPDF2.PdfReader(file)
        text = ''
        for page in reader.pages:
            text += page.extract_text() or ''

    if not text.strip():
        return "No readable text found in PDF."

    # Predict the category
    predicted_category = model.predict([text])[0]
    return predicted_category

