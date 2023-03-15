<?php

namespace Modules\Vms\Entities;


use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\SoftDeletes;
use Spatie\MediaLibrary\InteractsWithMedia;
use Illuminate\Database\Eloquent\Model;
use Spatie\MediaLibrary\HasMedia;
use Laravel\Sanctum\HasApiTokens;
use Illuminate\Notifications\Notifiable;
use Illuminate\Foundation\Auth\User as Authenticatable;
use PHPOpenSourceSaver\JWTAuth\Contracts\JWTSubject;

class VisitorRegistration extends Authenticatable implements HasMedia,JWTSubject
{

    use HasFactory, SoftDeletes, InteractsWithMedia, HasApiTokens, Notifiable;
    protected $connection = "vms";
    protected $table = 'users';
    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */

    protected $guarded = ['id', 'created_at', 'updated_at'];
    protected $appends = ['profile_image_url', 'cnic_front_url', 'cnic_back_url'];

    /**
     * The attributes that should be hidden for arrays.
     *
     * @var array
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    /**
     * The attributes that should be cast to native types.
     *
     * @var array
     */
    protected $casts = [
        'email_verified_at' => 'datetime',
    ];



    public function registerMediaCollections(): void
    {
        $this->addMediaCollection('user_profile');
        $this->addMediaCollection('cnic_front');
        $this->addMediaCollection('cnic_back');
    }


    public function getProfileImageUrlAttribute()
    {
        return $this->getFirstMediaUrl('user_profile');
    }

    public function getCnicFrontUrlAttribute()
    {
        return $this->getFirstMediaUrl('cnic_front');
    }

    public function getCnicBackUrlAttribute()
    {
        return $this->getFirstMediaUrl('cnic_back');
    }


    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    public function getJWTCustomClaims()
    {
        return [];
    }
}
