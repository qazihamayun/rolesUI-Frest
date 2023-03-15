<?php

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/


Route::prefix('vms')->group(function () {


    Route::group(['prefix' => 'my'], function () {
        Route::get('dashboard', 'VisitRequestController@dashboard')->name('my.dashboard');
        Route::get('create', 'VisitRequestController@create')->name('my.create');
        Route::Post('store', 'VisitRequestController@store')->name('my.store');
        Route::get('print/{id}', 'VisitRequestController@print')->name('my.print');

    });

    Route::middleware(['auth'])->group(function () {
        // Visitor Crud
        Route::get('/', 'VmsController@index');
        Route::resource('visitors', VisitorController::class);
        Route::post('request/{id}', 'VisitorController@requpdate')->name('visitor.info.update');

        // Report Controller 
        Route::group(['prefix' => 'reports'], function () {
            Route::get('visitors', 'ReportController@visitors')->name('reports.visitors');
        });

        Route::group(['prefix' => 'visitor'], function () {
            Route::get('visitor/print/{id}', 'VisitorController@print')->name('visitor.print');
            Route::get('epass', 'VisitorController@epass')->name('visitor.epass');
            Route::get('epass/update', 'VisitorController@epass_update')->name('epass.visitors.update');
            Route::get('info/{id}', 'VisitorController@info')->name('visitor.info');
            Route::resource('visit', VisitRequestController::class);
            Route::get('print/{id}', [VisitRequestController::class, 'print'])->name('visit.print');
        });
    });

    // visitor account and its routes 
    Route::group(['namespace' => 'Auth'], function () {
        Route::get('register', 'RegisterController@showRegistrationForm')->name('visitor.register.view');
        Route::post('register', 'RegisterController@register')->name('visitor.register');
        Route::post('visitor/logout', 'Auth\LoginController@logout')->name('visitor.auth.logout');
    });
});