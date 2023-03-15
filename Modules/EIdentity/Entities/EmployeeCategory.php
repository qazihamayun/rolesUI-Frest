<?php

namespace Modules\EIdentity\Entities;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class EmployeeCategory extends Model
{
    protected $table = 'employee_category';
    protected $connection = "eidentity";
    protected $fillable = ['title'];
}
