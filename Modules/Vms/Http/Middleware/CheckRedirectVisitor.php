<?php

namespace Modules\Vms\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class CheckRedirectVisitor
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
    //    if(auth()->guard('vms_user')->check()){
    //     return redirect()->route('visit.index');

    //        return redirect()->route('send him to visitor page route'); //write route name for visitor page
    //    }

        return $next($request);
    }
}