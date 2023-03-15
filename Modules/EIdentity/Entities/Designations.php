<?php

namespace Modules\EIdentity\Entities;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class Designations extends Model
{
    protected $table = 'designations';
    protected $connection = "eidentity";
    protected $fillable = ['title'];
}
