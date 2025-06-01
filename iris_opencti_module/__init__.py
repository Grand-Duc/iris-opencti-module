# Set the __iris_module_interface variable to the name of our main class. 
# When IRIS instantiates the python module, it looks for "module.__iris_module_interface"
# And then tries to instantiate the class "__iris_module_interface.__iris_module_interface", here 'IrisDummyModule.IrisDummyModule'. 
# That's why the python file must have the same name as the class.  

__iris_module_interface = "IrisOpenCTIModule"