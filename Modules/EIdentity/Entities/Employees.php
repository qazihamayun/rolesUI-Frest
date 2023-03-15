<?php

namespace Modules\EIdentity\Entities;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\SoftDeletes;

class Employees extends Model
{
    use SoftDeletes;

    protected $connection = "eidentity";
    protected $table = 'employees';
    protected $fillable = ['employee_uuid','grant_no','grant_desc','fund','fund_desc','user_id','department_id','department_name',
'personnel_no','employee_name','father_name','mobile_no','pr_code','ddo','ddo_desc','bps_id','bps',
'cash_center','employee_category_id','employee_category','guzzeted_id','designation_id','designation',
'designation_code','cnic','dob','date_of_appointment','profile_picture','name_of_working_section',
        'reporting_to_designation_id','ipms_department_id'];

    public function bpsMF(){
        return $this->belongsTo(BPS::class,'bps_id','id');
    }

    public function designationMF(){
        return $this->belongsTo(Designations::class,'designation_id','id');
    }

    public function employeeCategory(){
        return $this->belongsTo(EmployeeCategory::class,'employee_category_id','id');
    }

    public function guzzetedStatus(){
        return $this->belongsTo(GuzzetedStatus::class,'guzzeted_id','id');
    }

}
