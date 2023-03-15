<?php

namespace Modules\Vms\Entities;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class VehcileManufacturer extends Model
{
    use HasFactory;
    protected $connection = "vms";
}
