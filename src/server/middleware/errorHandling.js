function errorHandler(err, req, res, next) {
  console.error(err.stack);
  
  if (res.headersSent) {
    return next(err);
  }
  
  res.status(500);
  res.render('pages/error', { error: err.message || 'Internal Server Error' });
}

module.exports = errorHandler;