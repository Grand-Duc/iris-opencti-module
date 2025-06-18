# IRIS OpenCTI Module
An interface module to interact with OpenCTI.
> For the moment, this module is only compatible with **IRIS 2.5.0-beta.1** which is a **development** version.</br>
> This is due to the fact that all the production version does not share the actual case on ioc hook action and the Ioc class does not contain any link to the related case.
## Presentation
This module is designed to facilitate the integration of IRIS with OpenCTI, enabling the exchange of threat intelligence data between the two platforms (see Details part for more information).
- Cases : Cases created / updated / deleted in DFIR IRIS are mirrored in OpenCTI.
- Observables : Observables created / updated / deleted in DFIR IRIS are mirrored in OpenCTI.
- Assets : Assets created / updated / deleted in DFIR IRIS are mirrored in OpenCTI as a mix of observables and indicators.
- Tags : OpenCTI score and labels are applied to observables in IRIS through tags.
## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/Grand-Duc/iris-opencti-module.git
   ```
2. Compile the module using the buildnpush2iris.sh script:
   ```bash
   cd iris_opencti_module
   wget https://docs.dfir-iris.org/latest/development/modules/quick_start/buildnpush2iris.sh
   chmod +x buildnpush2iris.sh
   sudo ./buildnpush2iris.sh -a
   ```
3. Add the module to IRIS:
   - Go to the IRIS web interface.
   - Navigate to "Advanced > Modules" section (`https://{your_iris_url}/manage/modules`).
   - Click on "Add Module", fill the search bar with "**iris_opencti_module**" and click on "Validate module".
4. Configure the module.
By default, the module is disable becase it requires additionnal configuration variable.
</br>
In the module management page, click on the newly created module "IrisOpenCTI" to configure it:
   - Configure the OpenCTI connection settings:
     - OpenCTI URL: The URL of your OpenCTI instance.
     -  OpenCTI API Key: The API token for authentication with OpenCTI.
   - Apply by clicking on "Enable module".

## Details
### Cases
#### Case Creation / Update
Cases from DFIR IRIS are sent to OpenCTI.
</br>
Following variable are sent:
- Case name
- Case description

#### Case Deletion
For case deletion, only the associated IRIS case id is provided by the hook (while the case doesn't exist anymore). A solution is to delete the case in OpenCTI which name starts by `#{case_id} - `. Thus, it is strongly recommanded to NOT create cases in OpenCTI with a name starting by the same pattern.

---
### Observables
Observables from DFIR IRIS are sent to OpenCTI. Theses observables are linked to the actual case.
</br>
Following variable are sent:
- Observable value
- Observable type
Following variable are received:
- Observable score (saved as tag)
- Observable TLP is applied

#### Observable Creation
If the observable is not already present in OpenCTI, it will be created. A relationship is created between the observable and the case in OpenCTI.
#### Observable Update
Because IRIS does not send the former value of the observable, the module will compare the observables in OpenCTI and IRIS. A new observable will be created in OpenCTI if the observable is not already present and the former associated obersvable in OpenCTI will be deleted.

*Because some observables can be created by other authors or external sources, if the observable is not ONLY owned by IRIS, it will not be deleted in OpenCTI but the relationship with the case will be removed.*
#### Observable Deletion
> It is important to note that the deletion can't be done for the moment because IRIS only provide the ID of the deleted observable and not the observable itself. This means that the module can't know which observable to delete in OpenCTI. The deletion will be done by comparing the observables in OpenCTI and IRIS during **the next observable update from the same case**.

---
### Assets
Assets from DFIR IRIS are sent to OpenCTI as a mix of observables and indicators.
</br>
Following variable are sent:
- Asset name and description as System indicator
- Asset IP address as observable
- Asset domain as observable

## Future Work
From most probably to least probable, here are the future work that could be done on this module:
### Short Term
- Add observables types multi value IoCs (e.g. filename|md5). -> basic functionality already implemented.
- Add observable creation in comparison (in case an OpenCTI observable was deleted but still present in the IRIS case).
- Add optional configuration to decide is IRIS has priority over OpenCTI on deletion of observables.
### Long Term
- Add support for device objects. -> basic functionality already implemented.
- Add observable enrichment from OpenCTI (similar to IRIS VT Module).
- Add TTP observables support in IRIS.
- Add way to support events in OpenCTI by creating relationship.

## Development
This module does not require any additionnal Python library. GraphQL query are directly sent to OpenCTI API without using pycti because of Python version issue.
The module is composed of the following main files :
- `IrisOpenCTIConfig.py`: Configuration file for the module.
- `IrisOpenCTIModule.py`: Main module file containing the kook registering and action.
- `opencti_handler/opencti_handler.py`: Handler for OpenCTI interactions, including sending query to OpenCTI.
- `opencti_handler/query.py`: Contains GraphQL queries for OpenCTI (separated from the opencti_handler for clarity purpose).

The hook execution logs can be viewed from multiple places :
- In the IRIS web interface under "DIM Taks" section (https://{your_iris_url}/dim/tasks).
- In the "Quick actions" button (top right corner of the IRIS web interface) > "DIM Tasks"
- In the iriswebapp_worker docker container logs:
  ```bash
  docker logs -f iriswebapp_worker
  ```
- From the IRIS API by querying `https://{your_iris_url}dim/tasks/list/{rows_count}` (give less information)

It is to be noticed that while the task state can be marked as "success", the actual task execution can still fail. In this case, an error message can be displayed in the task details.

As mentioned in the presentation, this module is only compatible with IRIS 2.5.0-beta.1 for now. The explication behind that is that while the ioc hooks give the Ioc object, the Ioc class does not contain any link to the related case in older versions. However, the case is needed to create the observable in OpenCTI properly. The only seen option for now could be to use the search function to retrieve a case from an Ioc search, but this is not efficient and could lead to issues if multiple cases are found.