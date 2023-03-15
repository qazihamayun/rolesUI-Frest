<?php

namespace Modules\Vms\Http\Controllers\API;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:api')->get('/vms', function (Request $request) {
    return $request->user();
});


Route::prefix('vms/v1')->group(function () {
    Route::post('login', [AuthController::class, 'login']);
    Route::post('register', [AuthController::class, 'register']);

  
    // Route::post('forgot-password', [AuthController::class, 'sendResetLink']);
    // Get All Drop Down Menu 

    Route::prefix('dropdown')->group(function () {
        Route::get('departments', [DropDownController::class, 'departments']);
        Route::get('gates', [DropDownController::class, 'gates']);
    });


    Route::middleware('auth:vms_api')->group(function () {
        Route::resource('visitor', VisitorController::class);
        Route::post('check_time_slot', [VisitorController::class,'check_time_slot']);
        Route::get('visitor/status{status}', [VisitorController::class, 'visitor_status']);
        Route::group(['prefix' => 'visitors'], function () {
            Route::get('dashboard', [VisitorController::class, 'dashboard']);
        });

        Route::group(['prefix' => 'profile'], function () {
            Route::get('details', [UserController::class, 'details']);
        });
    });
});
