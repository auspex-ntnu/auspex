from fastapi import FastAPI


app = FastAPI()

@app.get("/logs")
async def logs():
    pass

@app.post("/pdf/generate")
async def generate_pdf_report(request: )