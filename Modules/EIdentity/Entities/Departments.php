<?php

namespace Modules\EIdentity\Entities;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class Departments extends Model
{
    protected $table = 'departments';
    protected $connection = "eidentity";
    protected $fillable = ['title'];
}
