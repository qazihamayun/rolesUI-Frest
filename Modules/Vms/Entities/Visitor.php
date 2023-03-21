<?php

namespace Modules\Vms\Entities;

use App\Models\User;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Support\Carbon;
use Illuminate\Database\Eloquent\Casts\Attribute;

class Visitor extends Model
{
    use HasFactory, SoftDeletes;
    protected $guarded = ['id', 'created_at', 'updated_at'];
    protected $appends = ['status_text', 'department_name', 'gate_name', 'visitor_name', 'visit_to_name'];
    protected $connection = "vms";


    protected function visitingDate(): Attribute
    {
        return Attribute::make(get: fn ($value, $attributes) => Carbon::create($value)->format("m/d/Y"));
    }



    public function user()
    {
        return $this->belongsTo(\Modules\Vms\Entities\VisitorRegistration::class, 'user_id');
    }

    public function creator()
    {
        return $this->belongsTo(\Modules\Vms\Entities\VisitorRegistration::class, 'creator_id');
    }

    // ALTER TABLE `visitors` ADD `visit_to_id` BIGINT NULL DEFAULT NULL AFTER `license_no`;
    public function vistedTo()
    {
        return $this->belongsTo(User::class, 'visit_to_id');
    }
    public function gate()
    {
        return $this->belongsTo(Gate::class);
    }

    public function department()
    {
        return $this->belongsTo(\Modules\Settings\Entities\Company::class, 'department_id');
    }

    public function getStatusTextAttribute()
    {

        $text = "Requested";
        switch ($this->status) {
            case 1:
                $text = "Visited";
                break;

            case 2:
                $text = "Requested";
                break;
            case 3:
                $text = "Approved";
                break;
            case 4:
                $text = "Reshudule";

                break;
        }


        return $text;
    }

    public function getDepartmentNameAttribute()
    {
        return \Modules\Settings\Entities\Company::where('id', $this->department_id)->value('title') ?? '';
    }

    public function getGateNameAttribute()
    {
        return Gate::where('id', $this->gate_id)->value('name') ?? '';
    }

    public function getVisitToNameAttribute()
    {
        return  User::where('id', $this->visit_to_id)->value('name') ?? '';
    }
    public function getVisitorNameAttribute()
    {
        return VisitorRegistration::where('id', $this->user_id)->value('name') ?? '';
    }

}

