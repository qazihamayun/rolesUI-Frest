<?php

namespace Modules\Vms\Entities;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Spatie\Activitylog\LogOptions;

class Gate extends Model
{
    use HasFactory, SoftDeletes;
    protected $guarded = ['id', 'created_at', 'updated_at'];
    protected $connection = "vms";




    public function visitors()
    {
        return $this->hasMany(Visitor::class, 'gate_id');
    }
}
