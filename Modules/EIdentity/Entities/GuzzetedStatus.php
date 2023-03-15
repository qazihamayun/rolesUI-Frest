<?php

namespace Modules\EIdentity\Entities;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\SoftDeletes;

class GuzzetedStatus extends Model
{
    use SoftDeletes;

    protected $connection = "eidentity";
    protected $table = 'guzzeted_status';
    protected $fillable = ['title'];
}
