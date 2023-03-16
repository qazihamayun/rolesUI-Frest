<?php

namespace Modules\EIdentity\Entities;


use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User as Authenticatable;
use PHPOpenSourceSaver\JWTAuth\Contracts\JWTSubject;
use Laravel\Sanctum\HasApiTokens;
use Illuminate\Support\Facades\Storage;

class Employees extends Authenticatable implements JWTSubject
{

    use HasFactory, SoftDeletes, HasApiTokens;

    protected $connection = "eidentity";
    protected $table = 'employees';
    protected $fillable = [
        'employee_uuid', 'grant_no', 'grant_desc', 'fund', 'fund_desc', 'user_id', 'department_id', 'department_name',
        'personnel_no', 'employee_name', 'father_name', 'mobile_no', 'pr_code', 'ddo', 'ddo_desc', 'bps_id', 'bps',
        'cash_center', 'employee_category_id', 'employee_category', 'guzzeted_id', 'designation_id', 'designation',
        'designation_code', 'cnic', 'dob', 'date_of_appointment', 'profile_picture', 'name_of_working_section',
        'reporting_to_designation_id', 'ipms_department_id'
    ];

    protected $hidden = [
        'password',
    ];

    protected $appends = ['profile_image_url'];


    public function bpsMF()
    {
        return $this->belongsTo(BPS::class, 'bps_id', 'id');
    }

    public function designationMF()
    {
        return $this->belongsTo(Designations::class, 'designation_id', 'id');
    }

    public function employeeCategory()
    {
        return $this->belongsTo(EmployeeCategory::class, 'employee_category_id', 'id');
    }

    public function guzzetedStatus()
    {
        return $this->belongsTo(GuzzetedStatus::class, 'guzzeted_id', 'id');
    }

    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    public function getJWTCustomClaims()
    {
        return [];
    }

    public function getProfileImageUrlAttribute()
    {
        $image_Url = "";
        if (!checkNullAndEmpty($this->profile_picture)) {
            $image_Url = Url('/') . Storage::url('public/eidentity/' . $this->profile_picture);
        }
      
        return $image_Url;
    }
}
