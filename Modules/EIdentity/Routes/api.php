<?php

namespace Modules\EIdentity\Http\Controllers\API;

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


Route::prefix('eidentity/v1')->group(function () {
    Route::post('login', [AuthController::class, 'login']);
});
