# Update data in UOM

This migrates the UOM DB post 17.4 and 18.1 changes

1. Deploy the lambda
2. The Security Group and Subnets are similar to the **Policy Engine lambda**
3. Set the following env variables
  * rds_endpoint
  * rds_user
  * rds_password
  * rds_db
  * rds_port
4. Allow event scheduler in the database ```aws rds modify-db-parameter-group --db-parameter-group-name <parameter-group-name> --parameters "ParameterName=event_scheduler,ParameterValue=ON,ApplyMethod=immediate”```
5. Run with payload ```{"approle" : {"update":true} }``` for 17.4 migration
6. Verify execution status with payload ```{"approle" : {} }``` to check status
7. Run with payload ```{"execsp" : true }``` for 18.1 migration on completion of previous step
8. Run with payload ```{"prodfix" : {"userId":"2bd9881b-b982-4da1-bdaf-62fab2fdde16","orgId":"4e113848-7b85-4cbd-9c0c-68402ee7eb1e"`i,"roleName": "practitioner"}}``` for PROD data fix (add GE Admin to Org)

---
Update ```INTERNAL``` group to ```EXTERNAL```
 ```'{"updGrpMembership":"<orgId>"}'```
