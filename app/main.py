from fastapi import FastAPI
from .cors import setup_cors


app = FastAPI()
setup_cors(app)


@app.get("/")
async def root():
    return {"message": "Hello World"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
