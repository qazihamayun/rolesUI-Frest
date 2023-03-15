<?php

namespace Modules\EIdentity\Entities;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\SoftDeletes;

class BPS extends Model
{
    use SoftDeletes;

    protected $table = 'bps';
    protected $connection = "eidentity";
    protected $fillable = ['title'];

}
