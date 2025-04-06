from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import RedirectResponse
import uvicorn
from DB_Util.MongoDB_Util import MongoDBHandler
from DB_Util.models.VulnItem import VulnItem, UpdateRequest, jsvalue
import traceback
from fastapi.middleware.cors import CORSMiddleware
from DB_Util.MongoDB_Util import *
from typing import Optional


MongoDBHandler = MongoDBHandler(db_name="vuln")


app = FastAPI(
    title="vuln",
    description="vuln",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["documentation"])
async def root():
    return RedirectResponse(url="/docs")


@app.post("/addNewDevice", tags=["add | update"])
async def addNewDevice(Device: VulnItem):
    try:
        Device = Device.dict()
        result = MongoDBHandler.insert_data(Device)
        return {"message": "Device inserted successfully"}
    except:
        traceback.print_exc()
        result = Device(data=Device, status_code=1)
    return result 



# @app.post("/updateDevice", tags=["add | update"])
# async def updateDevice(Org: VulnItem):
#     try:
#         Org = Org.dict()
#         MongoDBHandler.update_data(Org)
#         result = Org(data=Org, status_code=0)
#     except:
#         traceback.print_exc()
#         result = Org(data=Org, status_code=1)

#     return result

@app.put("/updateDevice", tags=["update"])
async def updateDevice(request: UpdateRequest):

    # Create filter query for the IP
    filter_query = {"ip": request.ip}

    # Call MongoDB update method
    success = MongoDBHandler.update_one_field(filter_query, request.update_field, request.new_value)

    if success:
        return {"message": "Field updated successfully"}
    else:
        return {"message": "Update failed or no matching document found"}


# @app.get("/listDeviceInfo", tags=["get"])
# async def listDeviceInfo(ip: str = Query(example="10.13.37.107"))->VulnItem:
#     found_doc = MongoDBHandler.find_one(query={"ip": ip})
#     return found_doc

@app.get("/listDeviceInfo", tags=["get"])
async def listDeviceInfo(ip: str = Query(example="10.13.37.107")) -> VulnItem:
    found_doc = MongoDBHandler.find_one(query={"ip": ip})

    if found_doc:
        # Return the found document as a VulnItem (Pydantic model)
        return VulnItem(**found_doc)
    else:
        return {"message": "Device not found"}

@app.get("/listAllDevices", tags=["get"])
async def listAllDevices():
    DevList = MongoDBHandler.get_all_data()
    return DevList


@app.delete("/removeDeviceFromDB", tags=["delete"])
async def removeDeviceFromDB(
    ip: str = Query(example="10.13.37.107")) -> VulnItem:
    try:
        delete_query = {"ip": ip}
        MongoDBHandler.delete_data(delete_query)
    
    except:
        traceback.print_exc()

    return 0
    
# @app.post("/receive-value", tags=["post"])
# async def receive_value(data: jsvalue):
#     js_value = data.value
#     subprocess.Popen(["python", "info_gathering.py", str(js_value)])
#     print(f"Called 'info_gathering.py' with value: {js_value}")
#     print("==============================")
#     return

# command to run -> cd DB_Util -> python -m uvicorn FastAPI_DB:app --reload


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000, log_level="info")
